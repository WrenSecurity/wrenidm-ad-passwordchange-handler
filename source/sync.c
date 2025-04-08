/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright (c) 2013-2014 ForgeRock AS. All rights reserved.
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
 * "Portions Copyrighted [2024-2025] [Wren Security]"
 **/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <ntsecapi.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <process.h>
#include "utils.h"
#include "network.h"
#include "log.h"
#include "version.h"

typedef struct {
    char *username;
    size_t ulength;
    char *password;
    size_t plength;
} PWCHANGE_CONTEXT;

LOG_QUEUE *log_handle;
LOG_LEVEL log_level = LOG_ERROR;
char log_path[MAX_PATH];
char log_path_idx[MAX_PATH];
HANDLE log_thr;
void *log_buffer[8192];

#define LOGHEAD "sync module init\r\n\r\n\t#######################################\r\n\t# %-36s#\r\n\t# Version: %-27s#\r\n\t# Revision: %-26s#\r\n\t# Build date: %s %-12s#\r\n\t#######################################\r\n"

static DWORD CALLBACK password_change_worker(LPVOID context) {
    PWCHANGE_CONTEXT *ctx = (PWCHANGE_CONTEXT *) context;
    if (ctx != NULL) {
        char *pwd_attr_id = NULL, *key_alias = NULL, *dir = NULL,
                *cert_file = NULL, *cert_pass = NULL, *hash = NULL,
                *user_b64 = NULL, *file = NULL, *xml = NULL, *idm_url = NULL, *idm_url_fixed = NULL,
                *auth_type = NULL, *auth_token0 = NULL, *auth_token1 = NULL,
                *key_alg = NULL;
        char *enc = NULL, *key = NULL;
        int xml_size = 0;
        AUTH_TYPE auth = NO_AUTH;
        ENCR_KEY_ALG alg = AES128;
        BOOL auth_token0_empty = FALSE;

        /* get network connection auth configuration */
        if (read_registry_key("authType", &auth_type)) {
            if (stricmp(auth_type, "basic") == 0) {
                auth = BASIC_AUTH;
                LOG(LOG_DEBUG, "password_change_worker(): authType set to \"%s\"", auth_type);
            } else if (stricmp(auth_type, "idm") == 0) {
                auth = IDM_HEADER_AUTH;
                LOG(LOG_DEBUG, "password_change_worker(): authType set to \"%s\"", auth_type);
            } else if (stricmp(auth_type, "cert") == 0) {
                auth = CERT_AUTH;
                LOG(LOG_DEBUG, "password_change_worker(): authType set to \"%s\"", auth_type);
            }
            free(auth_type);
        } else {
            LOG(LOG_WARNING, "password_change_worker(): authType is not set, network authentication disabled");
        }

        /* user name for basic/idm auth or cert file for ssl/tls auth */
        if (!read_registry_key("authToken0", &auth_token0)) {
            auth_token0 = strdup("");
            auth_token0_empty = TRUE;
        }
        LOG(LOG_DEBUG, "password_change_worker(): authToken0 set to \"%s\"", auth_token0);

        /* user password for basic/idm auth or password for ssl/tls auth certificate */
        if (!read_registry_key("authToken1", &auth_token1)) {
            auth_token1 = strdup("");
        }

        if (!read_registry_key("idmURL", &idm_url)
                || idm_url[0] == '\0' || count_char(idm_url, '$') != 1
                || (idm_url_fixed = string_replace(idm_url, "${samaccountname}", "%s")) == NULL) {
            LOG(LOG_ERROR, "password_change_worker(): invalid idmURL registry key value:\n%s",
                    idm_url == NULL ? "(null)" : idm_url);
        } else if (!read_registry_key("passwordAttr", &pwd_attr_id) || pwd_attr_id[0] == '\0') {
            LOG(LOG_ERROR, "password_change_worker(): invalid passwordAttr registry key value");
        } else if (!read_registry_key("keyAlias", &key_alias) || key_alias[0] == '\0') {
            LOG(LOG_ERROR, "password_change_worker(): invalid keyAlias registry key value");
        } else if (!read_registry_key("dataPath", &dir) || dir[0] == '\0' || !create_directory(dir)) {
            LOG(LOG_ERROR, "password_change_worker(): invalid dataPath registry key value");
        } else if (!read_registry_key("certFile", &cert_file) || cert_file[0] == '\0') {
            LOG(LOG_ERROR, "password_change_worker(): invalid certFile registry key value");
        } else if (ctx->username != NULL && ctx->password != NULL) {
            LOG(LOG_DEBUG, "password_change_worker(): processing user \"%s\"", ctx->username);
            if (!read_registry_key("certPassword", &cert_pass)) {
                cert_pass = strdup("");
            }

            /* encryption key type/size */
            if (read_registry_key("keyType", &key_alg) && key_alg[0] != '\0') {
                if (_strnicmp(key_alg, "aes256", 6) == 0) {
                    alg = AES256;
                } else if (_strnicmp(key_alg, "aes192", 6) == 0) {
                    alg = AES192;
                } else if (_strnicmp(key_alg, "aes128", 6) == 0) {
                    alg = AES128;
                } else {
                    LOG(LOG_WARNING, "password_change_worker(): invalid keyType registry key value [%s], defaulting to AES128", key_alg);
                }
            } else {
                LOG(LOG_WARNING, "password_change_worker(): empty keyType registry key value, defaulting to AES128");
            }

            if (key_alg != NULL) free(key_alg);

            /* encrypt password and key */
            if (encrypt(ctx->password, ctx->plength, cert_file, cert_pass, &enc, &key, alg)) {
                if ((hash = md5(ctx->username, ctx->ulength)) != NULL) {
                    /* hash user name - we'll use hash value to sort files */
                    asprintf(&file, "%s/%s-%lld.json", dir, hash, timestamp_id());
                    if (file != NULL) {
                        user_b64 = base64_encode(ctx->username, ctx->ulength, NULL);
                        xml_size = asprintf(&xml, json_payload_type(), pwd_attr_id, enc, key, key_alias);
                        if (xml != NULL) {
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
                            asprintf(&url, idm_url_fixed, ctx->username);
                            /* try to send change request */
                            if (auth == CERT_AUTH) {
                                n = net_connect_url(url, auth_token0_empty ? NULL : auth_token0, auth_token1, net_timeout(), &l);
                            } else {
                                n = net_connect_url(url, NULL, NULL, net_timeout(), &l);
                            }

                            if (n != NULL) {
                                const char *hdrs_bauth[1] = {h1};
                                const char *hdrs_iauth[2] = {h2, h3};
                                http_post(n, NULL,
                                        auth == BASIC_AUTH ? hdrs_bauth : auth == IDM_HEADER_AUTH ? hdrs_iauth : NULL,
                                        auth == BASIC_AUTH ? 1 : auth == IDM_HEADER_AUTH ? 2 : 0,
                                        xml, xml_size,
                                        &ret);
                                status = http_status(n, ret);
                                switch (status) {
                                    case 200:
                                    case 204:
                                        LOG(LOG_INFO, "password_change_worker(): change request for user \"%s\" succeeded", ctx->username);
                                        net_status = TRUE;
                                        break;
                                    case 404:
                                        LOG(LOG_WARNING, "password_change_worker(): server could not locate user \"%s\"", ctx->username);
                                        net_status = TRUE;
                                        break;
                                    default:
                                        LOG(LOG_ERROR, "password_change_worker(): change request for user \"%s\" failed, "
                                                "network status: %u, response: %s", ctx->username,
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

                            if (net_status == FALSE) {
                                /* network post failed - save change request to local store for later redelivery */
                                xml_size = asprintf(&xml, "%s%s", xml, user_b64);
                                if (xml != NULL) {
                                    LOG(LOG_WARNING, "password_change_worker(): saving change request to \"%s\" for redelivery, user \"%s\", size %d",
                                            file, ctx->username, xml_size);
                                    write_file(file, xml, xml_size);
                                }
                            }

                            if (xml != NULL) free(xml);
                            if (url != NULL) free(url);
                        }
                        if (user_b64 != NULL) free(user_b64);
                        if (file != NULL) free(file);
                    }
                    if (hash != NULL) free(hash);
                }
            } else {
                LOG(LOG_ERROR, "password_change_worker(): failed to encrypt user \"%s\" password", ctx->username);
            }
            if (enc != NULL) free(enc);
            if (key != NULL) free(key);
        }

        if (cert_pass != NULL) free(cert_pass);
        if (cert_file != NULL) free(cert_file);
        if (dir != NULL) free(dir);
        if (key_alias != NULL) free(key_alias);
        if (pwd_attr_id != NULL) free(pwd_attr_id);
        if (idm_url != NULL) free(idm_url);
        if (idm_url_fixed != NULL) free(idm_url_fixed);
        if (auth_token1 != NULL) free(auth_token1);
        if (auth_token0 != NULL) free(auth_token0);
        if (ctx->username != NULL) free(ctx->username);
        if (ctx->password != NULL) free(ctx->password);
        free(ctx);
    }
    return 0;
}

BOOLEAN __stdcall InitializeChangeNotify(void) {
    static volatile long s_init_once = 0;
    if (InterlockedCompareExchange(&s_init_once, 1, 0) == 0) {
        char *log_dir = NULL;
        if (!set_log_path(&log_dir)) {
            DEBUG("InitializeChangeNotify(): set_log_path failed");
        } else if (!create_directory(log_dir)) {
            DEBUG("InitializeChangeNotify(): create_directory failed");
        } else {
            log_handle = queue_init(log_buffer);
            _snprintf(log_path, sizeof (log_path), "%s/%s", log_dir, LOGNAME);
            _snprintf(log_path_idx, sizeof (log_path_idx), "%s/%s.%%d", log_dir, LOGNAME);
            log_level = get_log_level();
            if (!(log_thr = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) log_worker, log_handle, 0, NULL))) {
                DEBUG("InitializeChangeNotify(): create logger thread failed, error: %d", GetLastError());
                queue_delete(log_handle);
                log_handle = NULL;
            }
            LOG(LOG_ALWAYS, LOGHEAD, "WrenIDM Password Sync", VERSION, VERSION_GIT, __DATE__, __TIME__);
            free(log_dir);
            net_init();
        }
    }
    return TRUE;
}

NTSTATUS __stdcall PasswordChangeNotify(PUNICODE_STRING username, ULONG relativeId, PUNICODE_STRING newpassword) {
    size_t len;
    LPSTR pszTmp;
    BOOL status = FALSE;
    PWCHANGE_CONTEXT *ctx = NULL;
    if (username && newpassword) {
        ctx = (PWCHANGE_CONTEXT *) malloc(sizeof (PWCHANGE_CONTEXT));
        if (ctx != NULL) {
            ZeroMemory(ctx, sizeof (PWCHANGE_CONTEXT));
            len = WideCharToMultiByte(CP_UTF8, 0, username->Buffer, username->Length / sizeof (wchar_t), NULL, 0, NULL, NULL);
            if (len > 0) {
                ctx->username = (char *) malloc(len + 1);
                WideCharToMultiByte(CP_UTF8, 0, username->Buffer, username->Length / sizeof (wchar_t), ctx->username, (DWORD) len, NULL, NULL);
                ctx->username[len] = 0;
                ctx->ulength = len;
            }
            len = WideCharToMultiByte(CP_UTF8, 0, newpassword->Buffer, newpassword->Length / sizeof (wchar_t), NULL, 0, NULL, NULL);
            if (len > 0) {
                pszTmp = malloc(len + 1);
                pszTmp[len] = 0;
                WideCharToMultiByte(CP_UTF8, 0, newpassword->Buffer, newpassword->Length / sizeof (wchar_t), pszTmp, (DWORD) len, NULL, NULL);
                ctx->password = json_encode(pszTmp, len, &ctx->plength);
                free(pszTmp);
            }
            status = QueueUserWorkItem(password_change_worker, (PVOID) ctx, WT_EXECUTEDEFAULT);
        }
    }

    if (status == FALSE) {
        if (ctx != NULL) {
            if (ctx->username != NULL) {
                free(ctx->username);
            }
            if (ctx->password != NULL) {
                free(ctx->password);
            }
            free(ctx);
        }
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
            stop_logger("sync module exit", log_handle);
            WaitForSingleObject(log_thr, INFINITE);
            queue_delete(log_handle);
            net_shutdown();
        }
            break;
        default:
            break;
    }
    return TRUE;
}
