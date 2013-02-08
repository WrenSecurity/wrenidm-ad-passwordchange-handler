/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2013 ForgeRock Inc. All rights reserved.
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
#include <windows.h>
#include <ntsecapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "network.h"
#include "log.h"
#include "version.h"

typedef struct {
    wchar_t *username;
    DWORD ulength;
    wchar_t *password;
    DWORD plength;
} PWCHANGE_CONTEXT;

LOG_QUEUE *log_handle;
LOG_LEVEL log_level = LOG_ERROR;
wchar_t log_path[MAX_PATH];
wchar_t log_path_idx[MAX_PATH];
HANDLE log_thr;
void *log_buffer[8192];

#define LOGHEAD L"sync module init\r\n\r\n\t#######################################\r\n\t# %-36s#\r\n\t# Version: %-27s#\r\n\t# Revision: %-26s#\r\n\t# Build date: %s %-12s#\r\n\t#######################################\r\n"

static BOOL CALLBACK module_init(PINIT_ONCE ionce, void * param, void ** ctx) {
    BOOL status = FALSE;
    wchar_t *log_dir = NULL;
    if (!set_log_path(&log_dir)) {
        DEBUG("module_init(): set_log_path failed");
    } else if (!create_directory(log_dir)) {
        DEBUG("module_init(): create_directory failed");
    } else {
        log_handle = queue_init(log_buffer);
        swprintf(log_path, sizeof (log_path), L"%s/%s", log_dir, LOGNAME);
        swprintf(log_path_idx, sizeof (log_path_idx), L"%s/%s.%%d", log_dir, LOGNAME);
        log_level = get_log_level();
        if (!(log_thr = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) log_worker, log_handle, 0, NULL))) {
            DEBUG("module_init(): create logger thread failed, error: %d", GetLastError());
            queue_delete(log_handle);
            log_handle = NULL;
        } else {
            status = TRUE;
        }
        LOG(LOG_ALWAYS, LOGHEAD, L"OpenIDM Password Sync", TEXT(VERSION), VERSION_SVN, TEXT(__DATE__), TEXT(__TIME__));
        free(log_dir);
    }
    return status;
}

static void save_file(const wchar_t *file, const wchar_t *value) {
    FILE* pFile = _wfopen(file, L"wb");
    if (NULL == pFile) {
        LOG(LOG_ERROR, L"save_file(): file %s open error, %d", file, errno);
        return;
    }
    if (fwprintf(pFile, L"%s", value) < 0) {
        LOG(LOG_ERROR, L"save_file(): file %s write error, %d", file, errno);
    }
    fclose(pFile);
}

static void log_response(const char *data) {
    if (log_level == LOG_DEBUG) {
        if (data != NULL) {
            wchar_t *decoded = utf8_decode(data, NULL);
            if (decoded) {
                LOG(LOG_DEBUG, L"password_change_worker(): response:\n%s", decoded);
                free(decoded);
            }
        } else LOG(LOG_DEBUG, L"password_change_worker(): no response data");
    }
}

static VOID CALLBACK password_change_worker(PTP_CALLBACK_INSTANCE inst, void * context, PTP_WORK work) {
    PWCHANGE_CONTEXT *ctx = NULL;
    wchar_t *pwd_attr_id = NULL, *key_alias = NULL, *dir = NULL,
            *cert_file = NULL, *cert_pass = NULL, *hash = NULL,
            *user_b64 = NULL, *file = NULL, *xml = NULL, *idm_url = NULL, *idm_url_fixed = NULL,
            *encw = NULL, *keyw = NULL, *auth_type = NULL, *auth_token0 = NULL, *auth_token1 = NULL,
            *key_alg = NULL;
    char *enc = NULL, *key = NULL;
    int xml_size = 0;
    AUTH_TYPE auth = NO_AUTH;
    ENCR_KEY_ALG alg = AES128;

    /* get network connection auth configuration */
    if (read_registry_key(L"authType", &auth_type)) {
        if (wcsicmp(auth_type, L"basic") == 0) {
            auth = BASIC_AUTH;
            LOG(LOG_DEBUG, L"password_change_worker(): authType set to \"%s\"", auth_type);
        } else if (wcsicmp(auth_type, L"idm") == 0) {
            auth = IDM_HEADER_AUTH;
            LOG(LOG_DEBUG, L"password_change_worker(): authType set to \"%s\"", auth_type);
        } else if (wcsicmp(auth_type, L"cert") == 0) {
            auth = CERT_AUTH;
            LOG(LOG_DEBUG, L"password_change_worker(): authType set to \"%s\"", auth_type);
        }
        free(auth_type);
    } else {
        LOG(LOG_WARNING, L"password_change_worker(): authType is not set, network authentication disabled");
    }

    /* user name for basic/idm auth or cert file for ssl/tls auth */
    if (!read_registry_key(L"authToken0", &auth_token0)) {
        auth_token0 = _wcsdup(L"");
    }
    LOG(LOG_DEBUG, L"password_change_worker(): authToken0 set to \"%s\"", auth_token0);

    /* user password for basic/idm auth or password for ssl/tls auth certificate */
    if (!read_registry_key(L"authToken1", &auth_token1)) {
        auth_token1 = _wcsdup(L"");
    }

    if (!read_registry_key(L"idmURL", &idm_url)
            || idm_url[0] == '\0' || count_char(idm_url, L'$') != 1
            || (idm_url_fixed = string_replace(idm_url, L"${samaccountname}", L"%s")) == NULL) {
        LOG(LOG_ERROR, L"password_change_worker(): invalid idmURL registry key value:\n%s",
                idm_url == NULL ? L"(null)" : idm_url);
    } else if (!read_registry_key(L"passwordAttr", &pwd_attr_id) || pwd_attr_id[0] == '\0') {
        LOG(LOG_ERROR, L"password_change_worker(): invalid passwordAttr registry key value");
    } else if (!read_registry_key(L"keyAlias", &key_alias) || key_alias[0] == '\0') {
        LOG(LOG_ERROR, L"password_change_worker(): invalid keyAlias registry key value");
    } else if (!read_registry_key(L"dataPath", &dir) || dir[0] == '\0' || !create_directory(dir)) {
        LOG(LOG_ERROR, L"password_change_worker(): invalid dataPath registry key value");
    } else if (!read_registry_key(L"certFile", &cert_file) || cert_file[0] == '\0') {
        LOG(LOG_ERROR, L"password_change_worker(): invalid certFile registry key value");
    } else if ((ctx = (PWCHANGE_CONTEXT *) context) != NULL && ctx->username != NULL && ctx->password != NULL) {
        LOG(LOG_DEBUG, L"password_change_worker(): processing user \"%s\"", ctx->username);
        if (!read_registry_key(L"certPassword", &cert_pass)) {
            cert_pass = _wcsdup(L"");
        }

        /* encryption key type/size */
        if (read_registry_key(L"keyType", &key_alg) && key_alg[0] != '\0') {
            if (_wcsnicmp(key_alg, L"aes256", 6) == 0) {
                alg = AES256;
            } else if (_wcsnicmp(key_alg, L"aes192", 6) == 0) {
                alg = AES192;
            } else if (_wcsnicmp(key_alg, L"aes128", 6) == 0) {
                alg = AES128;
            } else {
                LOG(LOG_WARNING, L"password_change_worker(): invalid keyType registry key value [%s], defaulting to AES128", key_alg);
            }
        } else {
            LOG(LOG_WARNING, L"password_change_worker(): empty keyType registry key value, defaulting to AES128");
        }

        /* encrypt password and key */
        if (encrypt(ctx->password, cert_file, cert_pass, &enc, &key, alg)) {
            if ((hash = md5(ctx->username)) != NULL) {
                /* hash user name - we'll use hash value to sort files */
                idm_printf(&file, L"%s/%s-%lld.json", dir, hash, timestamp_id());
                if (file != NULL) {
                    if ((encw = utf8_decode(enc, NULL)) != NULL) {
                        if ((keyw = utf8_decode(key, NULL)) != NULL) {
                            if ((user_b64 = base64encode(ctx->username, ctx->ulength, NULL)) != NULL) {
                                xml_size = idm_printf(&xml, JSON_PAYLOAD, pwd_attr_id, encw, keyw, key_alias);
                                if (xml != NULL) {
                                    BOOL status = FALSE;
                                    wchar_t *url = NULL;
                                    int url_size = idm_printf(&url, idm_url_fixed, ctx->username);
                                    /* try to send change request */
                                    REQUEST_CONTEXT *rq = http_connect(url, TIMEOUT);
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
                                    if (rq && send_post_request(rq, NULL, xml, xml_size * sizeof (wchar_t)) && rq->dwReqCount == 1) {
                                        REQUEST_CONTEXT_INT *r = rq->lpRequest[0];
                                        if (r != NULL) {
                                            switch (r->dwStatusCode) {
                                                case 204:
                                                    LOG(LOG_INFO, L"password_change_worker(): change request for user \"%s\" succeeded", ctx->username);
                                                    status = TRUE;
                                                    break;
                                                case 404:
                                                    LOG(LOG_WARNING, L"password_change_worker(): server could not locate user \"%s\"", ctx->username);
                                                    log_response(r->lpBuffer);
                                                    status = TRUE;
                                                    break;
                                                default:
                                                    LOG(LOG_ERROR, L"password_change_worker(): change request for user \"%s\" failed. "\
                                                            L"Network status: %d, error: %d, code: %d, response size: %d", ctx->username, r->dwStatusCode,
                                                            r->dwErrorFlag, r->dwErrorCode, r->dwTotalSize);
                                                    log_response(r->lpBuffer);
                                            }
                                        }
                                    } else {
                                        LOG(LOG_ERROR, L"password_change_worker(): change request for user \"%s\" failed. "\
                                                L"Network connect/send error: %d, code: %d", ctx->username, rq->dwErrorFlag, rq->dwErrorCode);
                                    }
                                    http_close(rq);
                                    if (!status) {
                                        /* network post failed - save change request to local store for later re-delivery */
                                        xml_size = idm_printf(&xml, L"%s%s", xml, user_b64);
                                        if (xml != NULL) {
                                            LOG(LOG_DEBUG, L"password_change_worker(): saving json file \"%s\" for user \"%s\", size %d",
                                                    file, ctx->username, xml_size);
                                            save_file(file, xml);
                                        } else {
                                            LOG(LOG_ERROR, L"password_change_worker(): idm_printf for xml file content failed, error: %d", GetLastError());
                                        }
                                    }
                                    if (url) free(url);
                                    if (xml) free(xml);
                                } else {
                                    LOG(LOG_ERROR, L"password_change_worker(): idm_printf for xml failed, error: %d", GetLastError());
                                }
                                free(user_b64);
                            } else {
                                LOG(LOG_ERROR, L"password_change_worker(): base64encode for username failed, error: %d", GetLastError());
                            }
                            free(keyw);
                        } else {
                            LOG(LOG_ERROR, L"password_change_worker(): utf8_decode for key failed, error: %d", GetLastError());
                        }
                        free(encw);
                    } else {
                        LOG(LOG_ERROR, L"password_change_worker(): utf8_decode for enc failed, error: %d", GetLastError());
                    }
                    free(file);
                } else {
                    LOG(LOG_ERROR, L"password_change_worker(): idm_printf for file failed, error: %d", GetLastError());
                }
                free(hash);
            } else {
                LOG(LOG_ERROR, L"password_change_worker(): md5 for username failed, error: %d", GetLastError());
            }
            free(enc);
            free(key);
        } else {
            LOG(LOG_ERROR, L"password_change_worker(): encrypt for password failed, error: %d", GetLastError());
        }
    } else {
        LOG(LOG_ERROR, L"password_change_worker(): context is null");
    }
    if (key_alg) free(key_alg);
    if (idm_url_fixed) free(idm_url_fixed);
    if (idm_url) free(idm_url);
    if (pwd_attr_id) free(pwd_attr_id);
    if (key_alias) free(key_alias);
    if (dir) free(dir);
    if (cert_file) free(cert_file);
    if (cert_pass) free(cert_pass);
    if (ctx) {
        if (ctx->username) free(ctx->username);
        if (ctx->password) free(ctx->password);
        free(ctx);
    }
    free(auth_token0);
    free(auth_token1);
}

BOOLEAN __stdcall InitializeChangeNotify(void) {
    static INIT_ONCE s_init_once;
    InitOnceExecuteOnce(&s_init_once, module_init, NULL, NULL);
    return TRUE;
}

NTSTATUS __stdcall PasswordChangeNotify(PUNICODE_STRING username, ULONG relativeId, PUNICODE_STRING newpassword) {
    PWCHANGE_CONTEXT *ctx = NULL;
    PTP_WORK change = NULL;
    if (username && newpassword) {
        ctx = (PWCHANGE_CONTEXT *) malloc(sizeof (PWCHANGE_CONTEXT));
        if (ctx != NULL) {
            ZeroMemory(ctx, sizeof (PWCHANGE_CONTEXT));
            ctx->ulength = username->Length / sizeof (wchar_t);
            ctx->username = (wchar_t *) malloc((ctx->ulength + 1) * sizeof (wchar_t));
            ctx->plength = newpassword->Length / sizeof (wchar_t);
            ctx->password = (wchar_t *) malloc((ctx->plength + 3) * sizeof (wchar_t));
            if (ctx->username != NULL && ctx->password != NULL
                    && wcsncpy(ctx->username, username->Buffer, ctx->ulength) != NULL) {
                ctx->password[0] = '"';
                if (memcpy(ctx->password + 1, newpassword->Buffer, ctx->plength * sizeof (wchar_t)) != NULL) {
                    ctx->username[ctx->ulength] = 0;
                    ctx->password[ctx->plength + 1] = '"';
                    ctx->password[ctx->plength + 2] = 0;
                    ctx->plength = ctx->plength + 2;
                    change = CreateThreadpoolWork(password_change_worker, ctx, NULL);
                    if (change != NULL) {
                        SubmitThreadpoolWork(change);
                        CloseThreadpoolWork(change);
                    } else {
                        LOG(LOG_ERROR, L"PasswordChangeNotify(): CreateThreadpoolWork error: %d", GetLastError());
                        if (ctx->username) free(ctx->username);
                        if (ctx->password) free(ctx->password);
                        free(ctx);
                    }
                } else {
                    LOG(LOG_ERROR, L"PasswordChangeNotify(): memcpy error: %d", GetLastError());
                }
            } else {
                LOG(LOG_ERROR, L"PasswordChangeNotify(): %s, length: %d, password length: %d (error: %d)",
                        (ctx->username == NULL ? L"(empty)" : ctx->username), ctx->ulength, ctx->plength, GetLastError());
                if (ctx->username) free(ctx->username);
                if (ctx->password) free(ctx->password);
                free(ctx);
            }
        } else {
            LOG(LOG_ERROR, L"PasswordChangeNotify(): malloc error: %d", GetLastError());
        }
    } else {
        LOG(LOG_ERROR, L"PasswordChangeNotify(): empty username and/or new password");
    }
    return 0;
}

BOOLEAN __stdcall PasswordFilter(PUNICODE_STRING accountname, PUNICODE_STRING fullname, PUNICODE_STRING password, BOOLEAN setop) {
    return TRUE;
}

BOOL APIENTRY DllMain(HMODULE hmod, DWORD reason, void * resrv) {
    switch (reason) {
        case DLL_PROCESS_DETACH:
        {
            stop_logger(L"sync module exit", log_handle);
            WaitForSingleObject(log_thr, INFINITE);
            queue_delete(log_handle);
        }
            break;
        default:
            break;
    }
    return TRUE;
}