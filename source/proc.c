/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2012-2014 ForgeRock AS. All rights reserved.
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
 * "Portions Copyrighted [2012] [ForgeRock AS]"
 **/

#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <stdlib.h>
#include "network.h"
#include "log.h"
#include "proc.h"

#define MAXRETRIES  5
#define RETRYDELAY  250

static char * read_file(const char *file, int *size) {
    char *ret = NULL;
    HANDLE fd = INVALID_HANDLE_VALUE;
    BOOL status = FALSE;
    DWORD retry = 0, error = 0, br = 0, fs, fsh;
    OVERLAPPED rs;
    if (size) *size = 0;
    if (file != NULL) {
        do {
            fd = CreateFileA(file, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
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
                if (fs > 0 && (ret = (char *) malloc(fs + 1)) != NULL) {
                    if (!ReadFile(fd, ret, fs, &br, NULL)) {
                        free(ret);
                        ret = NULL;
                    } else {
                        br /= (sizeof (char));
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

DWORD CALLBACK file_worker(LPVOID ctx) {
    char *data_dir = (char *) ctx;
    char **file_list = NULL;
    char *idm_url = NULL, *auth_type = NULL, *auth_token0 = NULL, *auth_token1 = NULL,
            *data = NULL, *idm_url_fixed = NULL;
    char procd_file[32], proc_file[32];
    AUTH_TYPE auth = NO_AUTH;
    int i, file_count = 0, data_size = 0;
    BOOL auth_token0_empty = FALSE;

    if (data_dir != NULL) {
        if (read_registry_key("authType", &auth_type)) {
            if (stricmp(auth_type, "basic") == 0) {
                auth = BASIC_AUTH;
                LOG(LOG_DEBUG, "file_worker(): authType set to \"%s\"", auth_type);
            } else if (stricmp(auth_type, "idm") == 0) {
                auth = IDM_HEADER_AUTH;
                LOG(LOG_DEBUG, "file_worker(): authType set to \"%s\"", auth_type);
            } else if (stricmp(auth_type, "cert") == 0) {
                auth = CERT_AUTH;
                LOG(LOG_DEBUG, "file_worker(): authType set to \"%s\"", auth_type);
            }
            free(auth_type);
        } else {
            LOG(LOG_WARNING, "file_worker(): authType is not set, network authentication disabled");
        }

        /* user name for basic/idm auth or path to ssl/tls auth certificate file */
        if (!read_registry_key("authToken0", &auth_token0)) {
            auth_token0 = strdup("");
            auth_token0_empty = TRUE;
        }
        LOG(LOG_DEBUG, "file_worker(): authToken0 set to \"%s\"", auth_token0);

        /* user password for basic/idm auth or password for ssl/tls auth certificate */
        if (!read_registry_key("authToken1", &auth_token1)) {
            auth_token1 = strdup("");
        }

        if (!read_registry_key("idmURL", &idm_url) || idm_url[0] == '\0'
                || count_char(idm_url, '$') != 1
                || (idm_url_fixed = string_replace(idm_url, "${samaccountname}", "%s")) == NULL) {
            LOG(LOG_ERROR, "file_worker(): invalid idmURL registry key value:\n%s",
                    idm_url == NULL ? "(null)" : idm_url);
            if (idm_url) free(idm_url);
            if (idm_url_fixed) free(idm_url_fixed);
            free(auth_token0);
            free(auth_token1);
            InterlockedExchange((volatile long*) &file_worker_running, FALSE);
            return 0;
        }
        LOG(LOG_DEBUG, "file_worker(): idmURL set to \"%s\"", idm_url);

        file_list = traverse_directory(data_dir, &file_count);
        if (file_list != NULL) {
            LOG(LOG_DEBUG, "file_worker(): processing %s, %d file(s)", data_dir, file_count);
            for (i = 0; i < file_count; i++) {
                char *sep = strrchr(file_list[i], '/');
                if (sep != NULL) {
                    memcpy(proc_file, sep + 1, 32);
                } else continue;
                if (memcmp(proc_file, procd_file, 32) == 0) {
                    /* this (user) has been processed - delete file */
                    DeleteFile(file_list[i]);
                    continue;
                } else {
                    memcpy(procd_file, proc_file, 32);
                }
                LOG(LOG_DEBUG, "file_worker(): reading file %s", file_list[i]);
                data = read_file(file_list[i], &data_size);
                if (data != NULL) {
                    sep = strrchr(data, ']');
                    if (sep != NULL) {
                        DWORD usize = data_size - (sep + 1 - data);
                        char *user = base64_decode(sep + 1, usize, NULL);
                        if (user != NULL) {
                            BOOL net_status = FALSE;
                            char *url = NULL, *ret = NULL,
                                    *h0 = NULL, *h0b = NULL, *h1 = NULL, *h2 = NULL, *h3 = NULL;
                            net_t *n = NULL;
                            unsigned int status = 0, h0sz;
                            net_log_t l = {
                                NULL,
                                log_info,
                                log_warning,
                                log_error,
                                log_debug
                            };

                            h0sz = asprintf(&h0, "%s:%s", NOTNULL(auth_token0), NOTNULL(auth_token1));
                            h0b = base64_encode(h0, h0sz, NULL);
                            asprintf(&h1, "Authorization: Basic %s\r\n", NOTNULL(h0b));
                            asprintf(&h2, "X-OpenIDM-Username: %s\r\n", NOTNULL(auth_token0));
                            asprintf(&h3, "X-OpenIDM-Password: %s\r\n", NOTNULL(auth_token1));
                            asprintf(&url, idm_url_fixed, user);
                            /* try to send change request */
                            if (auth == CERT_AUTH) {
                                n = net_connect_url(url, auth_token0_empty ? NULL : auth_token0, auth_token1, NET_CONNECT_TIMEOUT, &l);
                            } else {
                                n = net_connect_url(url, NULL, NULL, NET_CONNECT_TIMEOUT, &l);
                            }

                            data[data_size - usize] = 0;

                            if (n != NULL) {
                                const char *hdrs_bauth[1] = {h1};
                                const char *hdrs_iauth[2] = {h2, h3};
                                http_post(n, NULL,
                                        auth == BASIC_AUTH ? hdrs_bauth : auth == IDM_HEADER_AUTH ? hdrs_iauth : NULL,
                                        auth == BASIC_AUTH ? 1 : auth == IDM_HEADER_AUTH ? 2 : 0,
                                        data, (data_size - usize),
                                        &ret);
                                status = http_status(n, ret);
                                switch (status) {
                                    case 200:
                                    case 204:
                                        LOG(LOG_INFO, "password_change_worker(): change request for user \"%s\" succeeded", user);
                                        net_status = TRUE;
                                        break;
                                    case 404:
                                        LOG(LOG_WARNING, "password_change_worker(): server could not locate user \"%s\"", user);
                                        net_status = TRUE;
                                        break;
                                    default:
                                        LOG(LOG_ERROR, "password_change_worker(): change request for user \"%s\" failed, "
                                                "network status: %u, response: %s", user,
                                                status, LOGEMPTY(ret));
                                }

                                net_close(n);
                                if (ret != NULL) free(ret);
                                if (h0 != NULL) free(h0);
                                if (h0b != NULL) free(h0b);
                                if (h1 != NULL) free(h1);
                                if (h2 != NULL) free(h2);
                                if (h3 != NULL) free(h3);
                            }
                            if (net_status) {
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
            LOG(LOG_DEBUG, "file_worker(): %s is empty", data_dir);
        }
        free(auth_token0);
        free(auth_token1);
        free(idm_url_fixed);
        free(idm_url);
    } else {
        LOG(LOG_ERROR, "file_worker(): invalid dataPath value");
    }
    InterlockedExchange((volatile long*) &file_worker_running, FALSE);
    return 0;
}

VOID CALLBACK file_time_worker(PVOID lpParam, BOOLEAN TimerOrWaitFired) {
    if (!InterlockedCompareExchange((volatile long*) &file_worker_running, TRUE, FALSE)) {
        file_worker(lpParam);
    } else {
        LOG(LOG_WARNING, "directory_time_worker(): file_time_worker is running");
    }
}
