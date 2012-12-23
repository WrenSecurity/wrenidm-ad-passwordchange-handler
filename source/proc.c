/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2012 ForgeRock Inc. All rights reserved.
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [2012] [Forgerock Inc]"
 **/

#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <stdlib.h>
#include "network.h"
#include "log.h"

#define MAXRETRIES  5
#define RETRYDELAY  250

static wchar_t * read_file(const wchar_t *file, int *size) {
    wchar_t *ret = NULL;
    HANDLE fd = INVALID_HANDLE_VALUE;
    BOOL status = FALSE;
    DWORD retry = 0, error = 0, br = 0, fs, fsh;
    OVERLAPPED rs;
    if (size) *size = 0;
    if (file != NULL) {
        do {
            fd = CreateFile(file, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (INVALID_HANDLE_VALUE == fd) {
                error = GetLastError();
                if (ERROR_SHARING_VIOLATION == error) {
                    retry += 1;
                    Sleep(RETRYDELAY);
                    continue;
                } else {
                    break;
                }
            }
            status = TRUE;
            break;
        } while (retry < MAXRETRIES);
        if (status == TRUE) {
            rs.Offset = 0;
            rs.OffsetHigh = 0;
            rs.hEvent = (HANDLE) 0;
            fs = GetFileSize(fd, &fsh);
            SetFilePointer(fd, 0, NULL, FILE_BEGIN);
            if (LockFileEx(fd, LOCKFILE_FAIL_IMMEDIATELY, 0, fs, fsh, &rs) == TRUE) {
                if (fs > 0 && (ret = (wchar_t *) malloc(fs * sizeof (wchar_t) + 1)) != NULL) {
                    if (!ReadFile(fd, ret, fs, &br, NULL)) {
                        free(ret);
                        ret = NULL;
                    } else {
                        br /= (sizeof (wchar_t));
                        ret[br] = 0;
                        if (size) *size = br;
                    }
                }
                UnlockFileEx(fd, 0, fs, fsh, &rs);
            }
            CloseHandle(fd);
        }
    }
    return ret;
}

static void log_response(const char *data) {
    if (log_level == LOG_DEBUG) {
        if (data != NULL) {
            wchar_t *decoded = utf8_decode(data, NULL);
            if (decoded) {
                LOG(LOG_DEBUG, L"file_worker(): response:\n%s", decoded);
                free(decoded);
            }
        } else LOG(LOG_DEBUG, L"file_worker(): no response data");
    }
}

void CALLBACK file_worker(PTP_CALLBACK_INSTANCE inst, void * ctx, PTP_WORK work) {
    wchar_t *data_dir = (wchar_t *) ctx;
    wchar_t **file_list = NULL;
    wchar_t *idm_url = NULL, *auth_type = NULL, *auth_token0 = NULL, *auth_token1 = NULL,
            *data = NULL, *idm_url_fixed = NULL;
    wchar_t procd_file[32], proc_file[32];
    AUTH_TYPE auth = NO_AUTH;
    REQUEST_CONTEXT *rq = NULL;
    int i, file_count = 0, data_size = 0;

    if (data_dir != NULL) {
        if (read_registry_key(L"authType", &auth_type)) {
            if (wcsicmp(auth_type, L"basic") == 0) {
                auth = BASIC_AUTH;
                LOG(LOG_DEBUG, L"file_worker(): authType set to \"%s\"", auth_type);
            } else if (wcsicmp(auth_type, L"idm") == 0) {
                auth = IDM_HEADER_AUTH;
                LOG(LOG_DEBUG, L"file_worker(): authType set to \"%s\"", auth_type);
            } else if (wcsicmp(auth_type, L"cert") == 0) {
                auth = CERT_AUTH;
                LOG(LOG_DEBUG, L"file_worker(): authType set to \"%s\"", auth_type);
            }
            free(auth_type);
        } else {
            LOG(LOG_WARNING, L"file_worker(): authType is not set, network authentication disabled");
        }

        /* user name for basic/idm auth or path to ssl/tls auth certificate file */
        if (!read_registry_key(L"authToken0", &auth_token0)) {
            auth_token0 = _wcsdup(L"");
        }
        LOG(LOG_DEBUG, L"file_worker(): authToken0 set to \"%s\"", auth_token0);

        /* user password for basic/idm auth or password for ssl/tls auth certificate */
        if (!read_registry_key(L"authToken1", &auth_token1)) {
            auth_token1 = _wcsdup(L"");
        }

        if (!read_registry_key(L"idmURL", &idm_url) || idm_url[0] == '\0'
                || count_char(idm_url, L'$') != 1
                || (idm_url_fixed = string_replace(idm_url, L"${samaccountname}", L"%s")) == NULL) {
            LOG(LOG_ERROR, L"file_worker(): invalid idmURL registry key value:\n%s",
                    idm_url == NULL ? L"(null)" : idm_url);
            if (idm_url) free(idm_url);
            if (idm_url_fixed) free(idm_url_fixed);
            free(auth_token0);
            free(auth_token1);
            return;
        }
        LOG(LOG_DEBUG, L"file_worker(): idmURL set to \"%s\"", idm_url);

        file_list = traverse_directory(data_dir, &file_count);
        if (file_list != NULL) {
            LOG(LOG_DEBUG, L"file_worker(): processing %s (%d files)", data_dir, file_count);
            for (i = 0; i < file_count; i++) {
                wchar_t *sep = wcsrchr(file_list[i], '/');
                if (sep != NULL) {
                    memcpy(proc_file, sep + 1, 32 * sizeof (wchar_t));
                } else continue;
                if (memcmp(proc_file, procd_file, 32 * sizeof (wchar_t)) == 0) {
                    /* this (user) has been processed - delete file */
                    DeleteFile(file_list[i]);
                    continue;
                } else {
                    memcpy(procd_file, proc_file, 32 * sizeof (wchar_t));
                }
                LOG(LOG_DEBUG, L"file_worker(): reading file %s", file_list[i]);
                data = read_file(file_list[i], &data_size);
                if (data != NULL) {
                    sep = wcsrchr(data, ']');
                    if (sep != NULL) {
                        DWORD usize = data_size - (sep + 1 - data);
                        wchar_t *user = base64decode(sep + 1, usize, NULL);
                        if (user != NULL) {
                            BOOL status = FALSE;
                            wchar_t *url = NULL;
                            int url_size = idm_printf(&url, idm_url_fixed, user);
                            /* try to send change request */
                            REQUEST_CONTEXT *rq = http_connect(url, TIMEOUT);
                            LOG(LOG_DEBUG, L"file_worker(): data from user \"%s\"", user);
                            if (rq) {
                                switch (auth) {
                                    case BASIC_AUTH:
                                        set_basic_auth(rq, auth_token0, auth_token1);
                                        break;
                                    case IDM_HEADER_AUTH:
                                        set_idmheader_auth(rq, auth_token0, auth_token1);
                                        break;
                                    case CERT_AUTH:
                                        set_cert_auth(rq, auth_token0, auth_token1);
                                        break;
                                }
                            }
                            if (rq && send_post_request(rq, NULL, data, (data_size - usize) * sizeof (wchar_t))
                                    && rq->dwReqCount == 1) {
                                REQUEST_CONTEXT_INT *r = rq->lpRequest[0];
                                if (r != NULL) {
                                    switch (r->dwStatusCode) {
                                        case 204:
                                            LOG(LOG_INFO, L"file_worker(): change request for user \"%s\" succeeded", user);
                                            status = TRUE;
                                            break;
                                        case 404:
                                            LOG(LOG_WARNING, L"file_worker(): server could not locate user \"%s\"", user);
                                            log_response(r->lpBuffer);
                                            status = TRUE;
                                            break;
                                        default:
                                            LOG(LOG_ERROR, L"file_worker(): change request for user \"%s\" failed. "\
                                                            L"Network status: %d, error: %d, code: %d, response size: %d", user, r->dwStatusCode,
                                                    r->dwErrorFlag, r->dwErrorCode, r->dwTotalSize);
                                            log_response(r->lpBuffer);
                                    }
                                }
                            } else {
                                LOG(LOG_ERROR, L"file_worker(): change request for user \"%s\" failed. "\
                                                L"Network connect/send error: %d, code: %d", user, rq->dwErrorFlag, rq->dwErrorCode);
                            }
                            http_close(rq);

                            if (status) {
                                /* change request succeeded or server said 'unknown user' - remove file */
                                DeleteFile(file_list[i]);
                            }

                            if (url) free(url);
                            free(user);
                        }
                    }
                    free(data);
                }
            }
            free_list(file_list, file_count);
        } else {
            LOG(LOG_DEBUG, L"file_worker(): %s is empty", data_dir);
        }

        free(auth_token0);
        free(auth_token1);
        free(idm_url_fixed);
        free(idm_url);
    } else {
        LOG(LOG_ERROR, L"file_worker(): invalid dataPath value");
    }
}

void CALLBACK file_time_worker(PTP_CALLBACK_INSTANCE inst, void * ctx, PTP_TIMER timer) {
    file_worker(NULL, ctx, NULL);
}
