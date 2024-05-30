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
 * "Portions Copyrighted [2024] [Wren Security]"
 **/

#define WIN32_LEAN_AND_MEAN
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <errno.h>
#include "network.h"
#include "log.h"
#include "proc.h"
#include "version.h"

LOG_QUEUE *log_handle;
LOG_LEVEL log_level = LOG_ERROR;
char log_path[MAX_PATH];
char log_path_idx[MAX_PATH];
void *log_buffer[8192];
SERVICE_STATUS ssts;
SERVICE_STATUS_HANDLE hssts;
static HANDLE hthr_event;
static HANDLE hkill_event;
volatile BOOL file_worker_running = FALSE;

#define SERVICE_NAME "WrenIDM Password Sync"
#define SERVICE_DESCR SERVICE_NAME " Service"
#define LOGHEAD "service init\r\n\r\n\t#######################################\r\n\t# %-36s#\r\n\t# Version: %-27s#\r\n\t# Revision: %-26s#\r\n\t# Build date: %s %-12s#\r\n\t#######################################\r\n"

typedef void (*param_handler)(void *);

struct command_line {
    const char* option;
    param_handler handler;
};

void WINAPI ServiceMain(DWORD argc, LPSTR* argv);
static void validate_service(int *argv);

static void show_usage() {
    fprintf(stdout, "\n%s usage:\n\n"\
            "install service:\n"\
            " idmsync.exe --install\n\n"\
            "uninstall service:\n"\
            " idmsync.exe --remove\n\n"\
            "start service:\n"\
            " idmsync.exe --start\n\n"\
            "stop service:\n"\
            " idmsync.exe --stop\n\n"\
            "query service:\n"\
            " idmsync.exe --status\n\n"\
            "validate configuration:\n"\
            " idmsync.exe --validate\n\n"\
            "generate encryption key:\n"\
            " idmsync.exe --key\n\n"\
            "encrypt password:\n"\
            " idmsync.exe --encrypt \"key\" \"password\"\n\n"\
            "build and version info:\n"\
            " idmsync.exe --version\n\n", SERVICE_DESCR);
}

static void key_service(void *argv) {
    char *key = NULL;
    size_t size = 0;
    if (generate_key(&key, &size))
        fprintf(stdout, "\n%s\n\n", key);
    if (key) free(key);
}

static void encrypt_service(void *argv) {
    char **a = (char **) argv;
    if (a != NULL) {
        char *out = NULL;
        if (encrypt_password(a[2], a[3], &out))
            fprintf(stdout, "\n%s\n\n", out);
        if (out) free(out);
    }
}

static void start_service(void *argv) {
    int validate_status = 0;
    SC_HANDLE schs, schscm;
    SERVICE_STATUS_PROCESS ssp;
    DWORD old_checkpoint, start_tick_count, wait_time, bytes_needed;

    validate_service(&validate_status);
    if (validate_status > 0) {
        fprintf(stdout, "Service validation failed, run --validate for detailed report\n");
        return;
    } else {
        fprintf(stdout, "Service validation successful\n");
    }

    schscm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == schscm) {
        show_windows_error(GetLastError());
        return;
    }
    schs = OpenServiceA(schscm, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (schs == NULL) {
        show_windows_error(GetLastError());
        CloseServiceHandle(schscm);
        return;
    }

    if (!QueryServiceStatusEx(schs, SC_STATUS_PROCESS_INFO, (LPBYTE) & ssp, sizeof (SERVICE_STATUS_PROCESS), &bytes_needed)) {
        show_windows_error(GetLastError());
        CloseServiceHandle(schs);
        CloseServiceHandle(schscm);
        return;
    }

    if (ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwCurrentState != SERVICE_STOP_PENDING) {
        fprintf(stdout, "Cannot start the service - it is already running\n");
        CloseServiceHandle(schs);
        CloseServiceHandle(schscm);
        return;
    }

    start_tick_count = GetTickCount();
    old_checkpoint = ssp.dwCheckPoint;

    while (ssp.dwCurrentState == SERVICE_STOP_PENDING) {
        wait_time = ssp.dwWaitHint / 10;
        if (wait_time < 1000)
            wait_time = 1000;
        else if (wait_time > 10000)
            wait_time = 10000;
        Sleep(wait_time);
        if (!QueryServiceStatusEx(schs, SC_STATUS_PROCESS_INFO, (LPBYTE) & ssp, sizeof (SERVICE_STATUS_PROCESS), &bytes_needed)) {
            show_windows_error(GetLastError());
            CloseServiceHandle(schs);
            CloseServiceHandle(schscm);
            return;
        }
        if (ssp.dwCheckPoint > old_checkpoint) {
            start_tick_count = GetTickCount();
            old_checkpoint = ssp.dwCheckPoint;
        } else {
            if (GetTickCount() - start_tick_count > ssp.dwWaitHint) {
                fprintf(stdout, "Timeout waiting for service to stop\n");
                CloseServiceHandle(schs);
                CloseServiceHandle(schscm);
                return;
            }
        }
    }

    if (!StartService(schs, 0, NULL)) {
        show_windows_error(GetLastError());
        CloseServiceHandle(schs);
        CloseServiceHandle(schscm);
        return;
    } else fprintf(stdout, "Service start pending...\n");

    if (!QueryServiceStatusEx(schs, SC_STATUS_PROCESS_INFO, (LPBYTE) & ssp, sizeof (SERVICE_STATUS_PROCESS), &bytes_needed)) {
        show_windows_error(GetLastError());
        CloseServiceHandle(schs);
        CloseServiceHandle(schscm);
        return;
    }

    start_tick_count = GetTickCount();
    old_checkpoint = ssp.dwCheckPoint;

    while (ssp.dwCurrentState == SERVICE_START_PENDING) {
        wait_time = ssp.dwWaitHint / 10;
        if (wait_time < 1000)
            wait_time = 1000;
        else if (wait_time > 10000)
            wait_time = 10000;
        Sleep(wait_time);
        if (!QueryServiceStatusEx(schs, SC_STATUS_PROCESS_INFO, (LPBYTE) & ssp, sizeof (SERVICE_STATUS_PROCESS), &bytes_needed)) {
            show_windows_error(GetLastError());
            break;
        }
        if (ssp.dwCheckPoint > old_checkpoint) {
            start_tick_count = GetTickCount();
            old_checkpoint = ssp.dwCheckPoint;
        } else {
            if (GetTickCount() - start_tick_count > ssp.dwWaitHint) {
                break;
            }
        }
    }

    if (ssp.dwCurrentState == SERVICE_RUNNING) {
        fprintf(stdout, "Service started successfully\n");
    } else {
        fprintf(stdout, "Service not started. \n");
        fprintf(stdout, "  Current State: %d\n", ssp.dwCurrentState);
        fprintf(stdout, "  Exit Code: %d\n", ssp.dwWin32ExitCode);
    }

    CloseServiceHandle(schs);
    CloseServiceHandle(schscm);
}

static void stop_service(void *argv) {
    SC_HANDLE schs, schscm;
    SERVICE_STATUS_PROCESS ssp;
    DWORD start_time = GetTickCount();
    DWORD bytes_needed;
    DWORD timeout = 30000;
    DWORD wait_time;

    schscm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == schscm) {
        show_windows_error(GetLastError());
        return;
    }

    schs = OpenServiceA(schscm, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
    if (schs == NULL) {
        show_windows_error(GetLastError());
        CloseServiceHandle(schscm);
        return;
    }

    if (!QueryServiceStatusEx(schs, SC_STATUS_PROCESS_INFO, (LPBYTE) & ssp, sizeof (SERVICE_STATUS_PROCESS), &bytes_needed)) {
        show_windows_error(GetLastError());
        goto stop_cleanup;
    }

    if (ssp.dwCurrentState == SERVICE_STOPPED) {
        fprintf(stdout, "Service is already stopped\n");
        goto stop_cleanup;
    }

    while (ssp.dwCurrentState == SERVICE_STOP_PENDING) {
        fprintf(stdout, "Service stop pending...\n");
        wait_time = ssp.dwWaitHint / 10;
        if (wait_time < 1000)
            wait_time = 1000;
        else if (wait_time > 10000)
            wait_time = 10000;
        Sleep(wait_time);
        if (!QueryServiceStatusEx(schs, SC_STATUS_PROCESS_INFO, (LPBYTE) & ssp, sizeof (SERVICE_STATUS_PROCESS), &bytes_needed)) {
            show_windows_error(GetLastError());
            goto stop_cleanup;
        }
        if (ssp.dwCurrentState == SERVICE_STOPPED) {
            fprintf(stdout, "Service stopped successfully\n");
            goto stop_cleanup;
        }
        if (GetTickCount() - start_time > timeout) {
            fprintf(stdout, "Service stop timed out\n");
            goto stop_cleanup;
        }
    }

    if (!ControlService(schs, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS) & ssp)) {
        show_windows_error(GetLastError());
        goto stop_cleanup;
    }

    while (ssp.dwCurrentState != SERVICE_STOPPED) {
        Sleep(ssp.dwWaitHint);
        if (!QueryServiceStatusEx(schs, SC_STATUS_PROCESS_INFO, (LPBYTE) & ssp, sizeof (SERVICE_STATUS_PROCESS), &bytes_needed)) {
            show_windows_error(GetLastError());
            goto stop_cleanup;
        }
        if (ssp.dwCurrentState == SERVICE_STOPPED)
            break;
        if (GetTickCount() - start_time > timeout) {
            fprintf(stdout, "Wait timed out\n");
            goto stop_cleanup;
        }
    }

    fprintf(stdout, "Service stopped successfully\n");

stop_cleanup:
    CloseServiceHandle(schs);
    CloseServiceHandle(schscm);
}

static void query_service(void *argv) {
    SC_HANDLE schs, schscm;
    SERVICE_STATUS_PROCESS ssp;
    DWORD bytes_needed;
    BOOL status = FALSE;
    schscm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schscm != NULL) {
        schs = OpenServiceA(schscm, SERVICE_NAME, SERVICE_QUERY_STATUS);
        if (schs != NULL) {
            if (QueryServiceStatusEx(schs, SC_STATUS_PROCESS_INFO,
                    (LPBYTE) & ssp, sizeof (SERVICE_STATUS_PROCESS), &bytes_needed)) {
                status = TRUE;
                if (ssp.dwCurrentState != SERVICE_STOPPED && ssp.dwCurrentState != SERVICE_STOP_PENDING) {
                    fprintf(stdout, "Service is running\n");
                } else {
                    fprintf(stdout, "Service is stopped\n");
                }
            }
            CloseServiceHandle(schs);
        } else {
            fprintf(stdout, "Service is not installed\n");
        }
        CloseServiceHandle(schscm);
    } else {
        fprintf(stdout, "No permission to query service info\n");
    }
}

static void remove_service(void *argv) {
    SC_HANDLE svc, scm;

    stop_service(argv);

    scm = OpenSCManagerA(0, 0, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        show_windows_error(GetLastError());
        return;
    }

    svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!svc) {
        show_windows_error(GetLastError());
        CloseServiceHandle(scm);
        return;
    }

    if (!DeleteService(svc)) {
        show_windows_error(GetLastError());
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return;
    }

    fprintf(stdout, "Service removed\n");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

static void install_service(void *argv) {
    SC_HANDLE svc, scm;
    SERVICE_DESCRIPTION sdesc;
    char modname[MAX_PATH];

    fprintf(stdout, "Installing %s service:\n", SERVICE_NAME);
    GetModuleFileNameA(NULL, modname, sizeof (modname));

    scm = OpenSCManagerA(0, 0, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        show_windows_error(GetLastError());
        return;
    }

    svc = CreateServiceA(scm, SERVICE_NAME, SERVICE_DESCR, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, modname, 0, 0, 0, NULL, NULL);
    if (!svc) {
        show_windows_error(GetLastError());
        CloseServiceHandle(scm);
        return;
    }

    sdesc.lpDescription = "This service provides secure password synchronization between Active Directory and WrenIDM";
    if (!ChangeServiceConfig2A(svc, SERVICE_CONFIG_DESCRIPTION, &sdesc)) {
        show_windows_error(GetLastError());
        CloseServiceHandle(svc);
        CloseServiceHandle(scm);
        return;
    }

    fprintf(stdout, "Service installed\n");
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
}

static void version_service(void *argv) {
    fprintf(stdout, "\n%s\n", SERVICE_DESCR);
    fprintf(stdout, " Version: %s\n", VERSION);
    fprintf(stdout, " Revision: %s\n", VERSION_GIT);
    fprintf(stdout, " Build date: %s %s\n\n", __DATE__, __TIME__);
}

static void validate_service(int *argv) {
    int st_inv = 0;
#define USERNAME_LENGTH 256
    DWORD username_len = USERNAME_LENGTH;
    char username[USERNAME_LENGTH];
    char *val = NULL, *val_r1 = NULL, *val_r2 = NULL;
    GetUserNameA(username, &username_len);
    if (argv == NULL) {
        fprintf(stdout, "\n%s\n", SERVICE_DESCR);
        fprintf(stdout, "\nValidating configuration parameters as user \"%s\"\n", username);
        fprintf(stdout, "\nLogging parameters:\nlogPath:\n");
    }
    read_registry_key("logPath", &val);
    validate_directory(val, argv == NULL ? NULL : &st_inv);
    if (val != NULL) {
        free(val);
        val = NULL;
    }
    if (argv == NULL) {
        fprintf(stdout, "\nlogLevel:\n");
    }
    read_registry_key("logLevel", &val);
    if (ISVALID(val) && (!strcmp(val, "error") || !strcmp(val, "info") || !strcmp(val, "warning") ||
            !strcmp(val, "fatal") || !strcmp(val, "debug"))) {
        if (argv == NULL) {
            fprintf(stdout, "   \"%s\" is a valid logLevel entry.\n", LOGEMPTY(val));
        }
    } else {
        if (argv == NULL) {
            fprintf(stdout, "   \"%s\" is not a valid logLevel entry. Accepted values are error, info, warning, fatal or debug.\n", LOGEMPTY(val));
        }
        st_inv++;
    }
    if (val != NULL) {
        free(val);
        val = NULL;
    }
    if (argv == NULL) {
        fprintf(stdout, "\nlogSize:\n");
    }
    read_registry_key("logSize", &val);
    errno = 0;
    if (ISVALID(val)) {
        int v = strtol(val, NULL, 10);
        if (v <= 0 || errno == ERANGE) {
            if (argv == NULL) {
                fprintf(stdout, "   \"%s\" is not a valid logSize entry. Will use default %d byte file size limit.\n", LOGEMPTY(val), MAX_FSIZE);
            }
        } else {
            if (argv == NULL) {
                fprintf(stdout, "   \"%s\" is a valid logSize entry.\n", LOGEMPTY(val));
            }
        }
    } else {
        if (argv == NULL) {
            fprintf(stdout, "   \"\" is not a valid logSize entry. Will use default %d byte file size limit.\n", MAX_FSIZE);
        }
    }
    if (val != NULL) {
        free(val);
        val = NULL;
    }
    if (argv == NULL) {
        fprintf(stdout, "\nService and data storage parameters:\ndataPath:\n");
    }
    read_registry_key("dataPath", &val);
    validate_directory(val, argv == NULL ? NULL : &st_inv);
    if (val != NULL) {
        free(val);
        val = NULL;
    }
    if (argv == NULL) {
        fprintf(stdout, "\npollEach:\n");
    }
    read_registry_key("pollEach", &val);
    errno = 0;
    if (ISVALID(val)) {
        int v = strtol(val, NULL, 10);
        if (v <= 0 || errno == ERANGE) {
            if (argv == NULL) {
                fprintf(stdout, "   \"%s\" is not a valid pollEach entry. Periodic directory poll is disabled.\n", LOGEMPTY(val));
            }
            st_inv++;
        } else {
            if (argv == NULL) {
                fprintf(stdout, "   \"%s\" is a valid pollEach entry.\n", LOGEMPTY(val));
            }
        }
    } else {
        if (argv == NULL) {
            fprintf(stdout, "   Periodic directory poll is disabled. Service is using file system notification events.\n");
        }
    }
    if (val != NULL) {
        free(val);
        val = NULL;
    }
    if (argv == NULL) {
        fprintf(stdout, "\nWrenIDM service parameters:\nidmURL:\n");
    }
    read_registry_key("idmURL", &val);
    if (validate_url(val)) {
        if (argv == NULL) {
            fprintf(stdout, "   \"%s\" is a valid idmURL entry.\n", LOGEMPTY(val));
        }
    } else {
        if (argv == NULL) {
            fprintf(stdout, "   \"%s\" is not a valid idmURL entry.\n", LOGEMPTY(val));
        }
        st_inv++;
    }
    if (val != NULL) {
        free(val);
        val = NULL;
    }
    if (argv == NULL) {
        fprintf(stdout, "\nkeyAlias:\n");
    }
    read_registry_key("keyAlias", &val);
    if (ISVALID(val)) {
        if (argv == NULL) {
            fprintf(stdout, "   \"%s\" is a valid keyAlias entry.\n", LOGEMPTY(val));
        }
    } else {
        if (argv == NULL) {
            fprintf(stdout, "   \"%s\" is not a valid keyAlias entry.\n", LOGEMPTY(val));
        }
        st_inv++;
    }
    if (val != NULL) {
        free(val);
        val = NULL;
    }
    if (argv == NULL) {
        fprintf(stdout, "\npasswordAttr:\n");
    }
    read_registry_key("passwordAttr", &val);
    if (ISVALID(val)) {
        if (argv == NULL) {
            fprintf(stdout, "   \"%s\" is a valid passwordAttr entry.\n", LOGEMPTY(val));
        }
    } else {
        if (argv == NULL) {
            fprintf(stdout, "   \"%s\" is not a valid passwordAttr entry.\n", LOGEMPTY(val));
        }
        st_inv++;
    }
    if (val != NULL) {
        free(val);
        val = NULL;
    }
    if (argv == NULL) {
        fprintf(stdout, "\nidm2Only:\n");
    }
    read_registry_key("idm2Only", &val);
    if (ISVALID(val)) {
        if (argv == NULL) {
            fprintf(stdout, "   Service is configured to run in WrenIDM 2.x compatibility mode.\n");
        }
    } else {
        if (argv == NULL) {
            fprintf(stdout, "   Service is configured to run with WrenIDM version 3.x or newer.\n");
        }
    }
    if (val != NULL) {
        free(val);
        val = NULL;
    }
    if (argv == NULL) {
        fprintf(stdout, "\nnetTimeout:\n");
    }
    read_registry_key("netTimeout", &val);
    errno = 0;
    if (ISVALID(val)) {
        int v = strtol(val, NULL, 10);
        if (v <= 0 || errno == ERANGE) {
            if (argv == NULL) {
                fprintf(stdout, "   \"%s\" is not a valid netTimeout entry. Will use default %d second network timeout.\n", LOGEMPTY(val), NET_CONNECT_TIMEOUT);
            }
        } else {
            if (argv == NULL) {
                fprintf(stdout, "   \"%s\" is a valid netTimeout entry.\n", LOGEMPTY(val));
            }
        }
    } else {
        if (argv == NULL) {
            fprintf(stdout, "   \"\" is not a valid netTimeout entry. Will use default %d second network timeout.\n", NET_CONNECT_TIMEOUT);
        }
    }
    if (val != NULL) {
        free(val);
        val = NULL;
    }
    if (argv == NULL) {
        fprintf(stdout, "\nauthType, authToken0 and authToken1:\n");
    }
    read_registry_key("authType", &val);
    read_registry_key("authToken0", &val_r1);
    read_registry_key("authToken1", &val_r2);
    if (ISVALID(val)) {
        if (!strcmp(val, "basic") || !strcmp(val, "idm")) {
            if (argv == NULL) {
                fprintf(stdout, "   Service is configured to use \"%s\" authentication\n", (!strcmp(val, "idm") ? "OpenIDM Header" : "HTTP Basic"));
            }
            if (ISVALID(val_r1) && ISVALID(val_r2)) {
                if (argv == NULL) {
                    fprintf(stdout, "   \"%s\" is a valid authType entry.\n", LOGEMPTY(val));
                }
            } else {
                if (argv == NULL) {
                    fprintf(stdout, "   invalid (empty) authToken0 or authToken1 entry.\n");
                }
                st_inv++;
            }
        } else if (!strcmp(val, "cert")) {
            if (argv == NULL) {
                fprintf(stdout, "   Service is configured to use \"Certificate\" authentication\n");
            }
            validate_pkcs12(val_r1, val_r2, argv == NULL ? NULL : &st_inv);
        } else {
            if (argv == NULL) {
                fprintf(stdout, "   \"%s\" invalid authType entry. Accepted values are basic, idm or cert.\n", LOGEMPTY(val));
            }
            st_inv++;
        }
    } else {
        if (argv == NULL) {
            fprintf(stdout, "   Service is configured to not use any authentication.\n");
        }
    }
    if (val != NULL) {
        free(val);
        val = NULL;
    }
    if (val_r1 != NULL) {
        free(val_r1);
        val_r1 = NULL;
    }
    if (val_r2 != NULL) {
        free(val_r2);
        val_r2 = NULL;
    }
    if (argv == NULL) {
        fprintf(stdout, "\nPassword encryption parameters:\ncertFile and certPassword:\n");
    }
    read_registry_key("certFile", &val);
    read_registry_key("certPassword", &val_r1);
    validate_pkcs12(val, val_r1, argv == NULL ? NULL : &st_inv);
    if (val != NULL) {
        free(val);
        val = NULL;
    }
    if (val_r1 != NULL) {
        free(val_r1);
        val_r1 = NULL;
    }
    if (argv != NULL) {
        *((int *) argv) = st_inv;
    }
}

static void kill_service() {
    SetEvent(hthr_event);
    Sleep(2000);
    SetEvent(hkill_event);
    fprintf(stdout, "Service exiting...\n");
}

static BOOL update_scm_status(DWORD dwCurrentState, DWORD dwWin32ExitCode, DWORD dwServiceSpecificExitCode, DWORD dwCheckPoint, DWORD dwWaitHint) {
    BOOL success;
    SERVICE_STATUS sstatus;
    sstatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    sstatus.dwCurrentState = dwCurrentState;
    if (dwCurrentState == SERVICE_START_PENDING) {
        sstatus.dwControlsAccepted = 0;
    } else {
        sstatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    }
    if (dwServiceSpecificExitCode == 0) {
        sstatus.dwWin32ExitCode = dwWin32ExitCode;
    } else {
        sstatus.dwWin32ExitCode = ERROR_SERVICE_SPECIFIC_ERROR;
    }
    sstatus.dwServiceSpecificExitCode = dwServiceSpecificExitCode;
    sstatus.dwCheckPoint = dwCheckPoint;
    sstatus.dwWaitHint = dwWaitHint;
    success = SetServiceStatus(hssts, &sstatus);
    if (!success) {
        kill_service();
    }
    return success;
}

static void terminate_service(int code, int wincode) {
    update_scm_status(SERVICE_STOPPED, wincode ? wincode : ERROR_SERVICE_SPECIFIC_ERROR, wincode ? 0 : code, 0, 0);
    return;
}

static void control_handler(DWORD request) {
    switch (request) {
        case SERVICE_CONTROL_INTERROGATE:
            break;
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            update_scm_status(SERVICE_STOP_PENDING, NO_ERROR, 0, 1, 5000);
            kill_service();
            update_scm_status(SERVICE_STOPPED, NO_ERROR, 0, 0, 0);
            CloseHandle(hthr_event);
            CloseHandle(hthr_event);
            fprintf(stdout, "Service stopped\n");
            return;
        default:
            break;
    }
    SetServiceStatus(hssts, &ssts);
    return;
}

int main(int argc, char ** argv) {
    SC_HANDLE svc, scm;
    int i;
    struct command_line params[] = {
        {"--install", install_service},
        {"--remove", remove_service},
        {"--stop", stop_service},
        {"--start", start_service},
        {"--status", query_service},
        {"--key", key_service},
        {"--encrypt", encrypt_service},
        {"--version", version_service},
        {"--validate", validate_service},
        {NULL}
    };
    SERVICE_TABLE_ENTRY service_table[] = {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION) ServiceMain},
        {NULL, NULL}
    };

    if (argc > 1) {
        for (i = 0; params[i].option; ++i) {
            if (!_stricmp(argv[1], params[i].option)) {
                if (!_stricmp(argv[1], "--validate")) {
                    params[i].handler(NULL);
                } else {
                    params[i].handler(argc == 4 ? argv : NULL);
                }
                return 0;
            }
        }
    } else {
        show_usage();
    }

    scm = OpenSCManagerA(0, 0, SC_MANAGER_CREATE_SERVICE);
    if (scm) {
        svc = OpenServiceA(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
        if (!svc) {
            fprintf(stdout, "Service is not installed or no permission to modify it\n");
            CloseServiceHandle(scm);
            return 0;
        }
    } else {
        fprintf(stdout, "Not enough privileges to open service control manager\n");
        return 0;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    StartServiceCtrlDispatcher(service_table);
    return 0;
}

static DWORD WINAPI directory_time_worker(LPVOID param) {
    HANDLE timer = NULL;
    HANDLE tick = NULL;
    DWORD *period = (DWORD *) param;
    BOOL cont = FALSE;
    char *data_dir = NULL;

    LOG(LOG_DEBUG, "directory_time_worker(): starting (will fire at %d second intervals)...", (*period));

    if (!read_registry_key("dataPath", &data_dir) || data_dir[0] == '\0' || !create_directory(data_dir)) {
        LOG(LOG_ERROR, "directory_time_worker(): invalid dataPath registry key value, exiting...");
        terminate_service(0, 0);
        kill_service();
        cont = FALSE;
    }

    timer = CreateTimerQueue();
    if (timer == NULL) {
        LOG(LOG_ERROR, "directory_time_worker(): CreateTimerQueue error (%d), exiting...", GetLastError());
        terminate_service(0, 0);
        kill_service();
        cont = FALSE;
    } else {
        cont = CreateTimerQueueTimer(&tick, timer,
                (WAITORTIMERCALLBACK) file_time_worker, (PVOID) data_dir, 1000, (*period) * 1000, WT_EXECUTELONGFUNCTION);
    }

    if (cont) {
        while (WaitForSingleObject(hthr_event, INFINITE) != WAIT_OBJECT_0) {
            Sleep(1000);
        }
    }

    if (timer != NULL) {
        DeleteTimerQueue(timer);
    }
    if (data_dir) free(data_dir);
    LOG(LOG_DEBUG, "directory_time_worker(): finished");
    return 0;
}

static DWORD WINAPI directory_worker(LPVOID param) {
    HANDLE hchange, handles[2];
    BOOL cont = TRUE;
    BOOL status = FALSE;
    char *data_dir = NULL;

    LOG(LOG_DEBUG, "directory_worker(): starting...");

    if (!read_registry_key("dataPath", &data_dir) || data_dir[0] == '\0' || !create_directory(data_dir)) {
        LOG(LOG_ERROR, "directory_worker(): invalid dataPath registry key value, exiting...");
        terminate_service(0, 0);
        kill_service();
        cont = FALSE;
    }

    hchange = FindFirstChangeNotificationA(data_dir, FALSE, FILE_NOTIFY_CHANGE_FILE_NAME);
    if (hchange == INVALID_HANDLE_VALUE) {
        LOG(LOG_ERROR, "directory_worker(): FindFirstChangeNotification error (%d), exiting...", GetLastError());
        terminate_service(0, 0);
        kill_service();
        cont = FALSE;
    }

    if (hchange != INVALID_HANDLE_VALUE) {
        LOG(LOG_DEBUG, "directory_worker(): started");
    }

    handles[0] = hchange;
    handles[1] = hthr_event;

    while (cont) {
        if (WaitForMultipleObjects(2, handles, FALSE, INFINITE) - WAIT_OBJECT_0 == 0) {
            if (!InterlockedCompareExchange((volatile long*) &file_worker_running, TRUE, FALSE)) {
                status = QueueUserWorkItem(file_worker, (PVOID) data_dir, WT_EXECUTEDEFAULT);
                if (status == FALSE) {
                    LOG(LOG_ERROR, "directory_worker(): QueueUserWorkItem error (%d)", GetLastError());
                }
            } else {
                LOG(LOG_WARNING, "directory_worker(): file_worker is running");
            }
            if (FindNextChangeNotification(hchange) == FALSE) {
                LOG(LOG_ERROR, "directory_worker(): FindNextChangeNotification error (%d), exiting...", GetLastError());
                terminate_service(0, 0);
                kill_service();
                cont = FALSE;
            }
        } else cont = FALSE;
    }
    FindCloseChangeNotification(hchange);
    if (data_dir) free(data_dir);
    LOG(LOG_DEBUG, "directory_worker(): finished");
    return 0;
}

void WINAPI ServiceMain(DWORD argc, LPSTR* argv) {
    int timeout;
    HANDLE wrk_thr, log_thr;
    HANDLE handles[3];
    char *log_dir = NULL, *poll_each = NULL;

    ssts.dwServiceType = SERVICE_WIN32;
    ssts.dwCurrentState = SERVICE_START_PENDING;
    ssts.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ssts.dwWin32ExitCode = 0;
    ssts.dwServiceSpecificExitCode = 0;
    ssts.dwCheckPoint = 0;
    ssts.dwWaitHint = 0;

    hssts = RegisterServiceCtrlHandlerA(SERVICE_NAME, (LPHANDLER_FUNCTION) control_handler);
    if (hssts == (SERVICE_STATUS_HANDLE) 0) {
        DEBUG("ServiceMain(): registering control handler failed, error: %d", GetLastError());
        show_windows_error(GetLastError());
        return;
    }

    hkill_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    hthr_event = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!hkill_event || !hthr_event) {
        ssts.dwCurrentState = SERVICE_STOPPED;
        ssts.dwWin32ExitCode = -1;
        SetServiceStatus(hssts, &ssts);
        DEBUG("ServiceMain(): create events failed, error: %d", GetLastError());
        show_windows_error(GetLastError());
        return;
    }

    if (!set_log_path(&log_dir)) {
        ssts.dwCurrentState = SERVICE_STOPPED;
        ssts.dwWin32ExitCode = -1;
        SetServiceStatus(hssts, &ssts);
        DEBUG("ServiceMain(): set_log_path failed");
        return;
    }

    if (!create_directory(log_dir)) {
        ssts.dwCurrentState = SERVICE_STOPPED;
        ssts.dwWin32ExitCode = -1;
        SetServiceStatus(hssts, &ssts);
        DEBUG("ServiceMain(): create_directory for %s failed", log_dir);
        return;
    }

    net_init();
    log_handle = queue_init(log_buffer);
    _snprintf(log_path, sizeof (log_path), "%s/%s", log_dir, LOGNAME);
    _snprintf(log_path_idx, sizeof (log_path_idx), "%s/%s.%%d", log_dir, LOGNAME);
    log_level = get_log_level();
    free(log_dir);

    log_thr = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE) log_worker, log_handle, 0, NULL);
    if (!log_thr) {
        ssts.dwCurrentState = SERVICE_STOPPED;
        ssts.dwWin32ExitCode = -1;
        SetServiceStatus(hssts, &ssts);
        DEBUG("ServiceMain(): create logger thread failed, error: %d", GetLastError());
        show_windows_error(GetLastError());
        queue_delete(log_handle);
        log_handle = NULL;
        return;
    }

    LOG(LOG_ALWAYS, LOGHEAD, SERVICE_DESCR, TEXT(VERSION), VERSION_GIT, TEXT(__DATE__), TEXT(__TIME__));

    ssts.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hssts, &ssts);

    if (!read_registry_key("pollEach", &poll_each) || poll_each[0] == '\0') {
        if (poll_each) free(poll_each);
        timeout = 0;
    } else {
        errno = 0;
        timeout = strtol(poll_each, NULL, 10);
        if (timeout <= 0 || errno == ERANGE) {
            LOG(LOG_ERROR, "ServiceMain(): invalid pollEach registry key value. Periodic directory poll is disabled - using default file system event worker");
            timeout = 0;
        }
        free(poll_each);
    }

    if (timeout == 0) {
        LOG(LOG_INFO, "ServiceMain(): periodic directory poll is disabled - using default file system event worker");
    }

    wrk_thr = CreateThread(NULL, 0,
            (LPTHREAD_START_ROUTINE) (timeout == 0 ? directory_worker : directory_time_worker),
            &timeout, 0, NULL);
    if (!wrk_thr) {
        ssts.dwCurrentState = SERVICE_STOPPED;
        ssts.dwWin32ExitCode = -1;
        SetServiceStatus(hssts, &ssts);
        LOG(LOG_ERROR, "ServiceMain(): create worker thread failed, error: %d", GetLastError());
    }
    handles[0] = wrk_thr;
    handles[1] = hkill_event;
    handles[2] = hthr_event;
    WaitForMultipleObjects(3, handles, TRUE, INFINITE);
    stop_logger("service exit", log_handle);
    WaitForSingleObject(log_thr, INFINITE);
    CloseHandle(wrk_thr);
    CloseHandle(log_thr);
    Sleep(2000);
    queue_delete(log_handle);
    net_shutdown();
}
