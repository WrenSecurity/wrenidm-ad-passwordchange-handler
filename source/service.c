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
wchar_t log_path[MAX_PATH];
wchar_t log_path_idx[MAX_PATH];
void *log_buffer[8192];
SERVICE_STATUS ssts;
SERVICE_STATUS_HANDLE hssts;
static HANDLE hthr_event;
static HANDLE hkill_event;

#define SERVICE_NAME L"OpenIDM Password Sync"
#define SERVICE_DESCR SERVICE_NAME L" Service"
#define LOGHEAD L"service init\r\n\r\n\t#######################################\r\n\t# %-36s#\r\n\t# Version: %-27s#\r\n\t# Revision: %-26s#\r\n\t# Build date: %s %-12s#\r\n\t#######################################\r\n"

typedef void (*param_handler)(void *);

struct command_line {
    const char* option;
    param_handler handler;
};

void WINAPI ServiceMain(DWORD argc, LPSTR* argv);

static void show_usage() {
    fwprintf(stdout, L"\n%s usage:\n\n"\
            L"install service:\n"\
            L" idmsync.exe --install\n\n"\
            L"uninstall service:\n"\
            L" idmsync.exe --remove\n\n"\
            L"start service:\n"\
            L" idmsync.exe --start\n\n"\
            L"stop service:\n"\
            L" idmsync.exe --stop\n\n"\
            L"query service:\n"\
            L" idmsync.exe --status\n\n"\
            L"generate encryption key:\n"\
            L" idmsync.exe --key\n\n"\
            L"encrypt password:\n"\
            L" idmsync.exe --encrypt \"key\" \"password\"\n\n"\
            L"build and version info:\n"\
            L" idmsync.exe --version\n\n", SERVICE_DESCR);
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
    SC_HANDLE schs, schscm;
    SERVICE_STATUS_PROCESS ssp;
    DWORD old_checkpoint, start_tick_count, wait_time, bytes_needed;

    schscm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == schscm) {
        show_windows_error(GetLastError());
        return;
    }
    schs = OpenService(schscm, SERVICE_NAME, SERVICE_ALL_ACCESS);
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

    schscm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (NULL == schscm) {
        show_windows_error(GetLastError());
        return;
    }

    schs = OpenService(schscm, SERVICE_NAME, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
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
    schscm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (schscm != NULL) {
        schs = OpenService(schscm, SERVICE_NAME, SERVICE_QUERY_STATUS);
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

    scm = OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        show_windows_error(GetLastError());
        return;
    }

    svc = OpenService(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
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
    wchar_t modname[MAX_PATH];

    fwprintf(stdout, L"Installing %s service:\n", SERVICE_NAME);
    GetModuleFileName(NULL, modname, sizeof (modname));

    scm = OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        show_windows_error(GetLastError());
        return;
    }

    svc = CreateService(scm, SERVICE_NAME, SERVICE_DESCR, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START, SERVICE_ERROR_NORMAL, modname, 0, 0, 0, NULL, NULL);
    if (!svc) {
        show_windows_error(GetLastError());
        CloseServiceHandle(scm);
        return;
    }

    sdesc.lpDescription = L"This service provides secure password synchronization between Active Directory and OpenIDM";
    if (!ChangeServiceConfig2(svc, SERVICE_CONFIG_DESCRIPTION, &sdesc)) {
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
    fwprintf(stdout, L"\n%s\n", SERVICE_DESCR);
    fprintf(stdout, " Version: %s\n", VERSION);
    fwprintf(stdout, L" Revision: %s\n", VERSION_SVN);
    fprintf(stdout, " Build date: %s %s\n\n", __DATE__, __TIME__);
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
        {NULL}
    };
    SERVICE_TABLE_ENTRY service_table[] = {
        {SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION) ServiceMain},
        {NULL, NULL}
    };

    if (argc > 1) {
        for (i = 0; params[i].option; ++i) {
            if (!_stricmp(argv[1], params[i].option)) {
                params[i].handler(argc == 4 ? argv : NULL);
                return 0;
            }
        }
    } else {
        show_usage();
    }

    scm = OpenSCManager(0, 0, SC_MANAGER_CREATE_SERVICE);
    if (scm) {
        svc = OpenService(scm, SERVICE_NAME, SERVICE_ALL_ACCESS);
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
    PTP_TIMER timer = NULL;
    DWORD *period = (DWORD *) param;
    BOOL cont = TRUE;
    FILETIME time;
    ULARGE_INTEGER utime;
    wchar_t *data_dir = NULL;

    LOG(LOG_DEBUG, L"directory_time_worker(): starting (will fire at %d second intervals)...", (*period));

    if (!read_registry_key(L"dataPath", &data_dir) || data_dir[0] == '\0' || !create_directory(data_dir)) {
        LOG(LOG_ERROR, L"directory_time_worker(): invalid dataPath registry key value, exiting...");
        terminate_service(0, 0);
        kill_service();
        cont = FALSE;
    }

    timer = CreateThreadpoolTimer(file_time_worker, data_dir, NULL);
    if (timer == NULL) {
        LOG(LOG_ERROR, L"directory_time_worker(): CreateThreadpoolTimer error (%d), exiting...", GetLastError());
        terminate_service(0, 0);
        kill_service();
        cont = FALSE;
    }

    if (cont) {
        utime.QuadPart = (LONGLONG) -(1 * 10 * 1000 * 1000);
        time.dwHighDateTime = utime.HighPart;
        time.dwLowDateTime = utime.LowPart;
        SetThreadpoolTimer(timer, &time, (*period) * 1000, 0);
        while (WaitForSingleObject(hthr_event, INFINITE) != WAIT_OBJECT_0) {
            Sleep(1000);
        }
    }

    if (timer != NULL) {
        SetThreadpoolTimer(timer, NULL, 0, 0);
        CloseThreadpoolTimer(timer);
    }
    if (data_dir) free(data_dir);
    LOG(LOG_DEBUG, L"directory_time_worker(): finished");
    return 0;
}

static DWORD WINAPI directory_worker(LPVOID param) {
    HANDLE hchange, handles[2];
    BOOL cont = TRUE;
    PTP_WORK change = NULL;
    wchar_t *data_dir = NULL;

    LOG(LOG_DEBUG, L"directory_worker(): starting...");

    if (!read_registry_key(L"dataPath", &data_dir) || data_dir[0] == '\0' || !create_directory(data_dir)) {
        LOG(LOG_ERROR, L"directory_worker(): invalid dataPath registry key value, exiting...");
        terminate_service(0, 0);
        kill_service();
        cont = FALSE;
    }

    hchange = FindFirstChangeNotification(data_dir, FALSE, FILE_NOTIFY_CHANGE_FILE_NAME);
    if (hchange == INVALID_HANDLE_VALUE) {
        LOG(LOG_ERROR, L"directory_worker(): FindFirstChangeNotification error (%d), exiting...", GetLastError());
        terminate_service(0, 0);
        kill_service();
        cont = FALSE;
    }

    if (hchange != INVALID_HANDLE_VALUE) {
        LOG(LOG_DEBUG, L"directory_worker(): started");
    }

    handles[0] = hchange;
    handles[1] = hthr_event;

    while (cont) {
        if (WaitForMultipleObjects(2, handles, FALSE, INFINITE) - WAIT_OBJECT_0 == 0) {
            change = CreateThreadpoolWork(file_worker, data_dir, NULL);
            if (change != NULL) {
                SubmitThreadpoolWork(change);
                CloseThreadpoolWork(change);
            } else {
                LOG(LOG_ERROR, L"directory_worker(): CreateThreadpoolWork error (%d)", GetLastError());
            }
            if (FindNextChangeNotification(hchange) == FALSE) {
                LOG(LOG_ERROR, L"directory_worker(): FindNextChangeNotification error (%d), exiting...", GetLastError());
                terminate_service(0, 0);
                kill_service();
                cont = FALSE;
            }
        } else cont = FALSE;
    }
    FindCloseChangeNotification(hchange);
    if (data_dir) free(data_dir);
    LOG(LOG_DEBUG, L"directory_worker(): finished");
    return 0;
}

void WINAPI ServiceMain(DWORD argc, LPSTR* argv) {
    int error, timeout;
    HANDLE wrk_thr, log_thr;
    HANDLE handles[3];
    wchar_t *log_dir = NULL, *poll_each = NULL;

    ssts.dwServiceType = SERVICE_WIN32;
    ssts.dwCurrentState = SERVICE_START_PENDING;
    ssts.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ssts.dwWin32ExitCode = 0;
    ssts.dwServiceSpecificExitCode = 0;
    ssts.dwCheckPoint = 0;
    ssts.dwWaitHint = 0;

    hssts = RegisterServiceCtrlHandler(SERVICE_NAME, (LPHANDLER_FUNCTION) control_handler);
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

    log_handle = queue_init(log_buffer);
    swprintf(log_path, sizeof (log_path), L"%s/%s", log_dir, LOGNAME);
    swprintf(log_path_idx, sizeof (log_path_idx), L"%s/%s.%%d", log_dir, LOGNAME);
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

    LOG(LOG_ALWAYS, LOGHEAD, SERVICE_DESCR, TEXT(VERSION), VERSION_SVN, TEXT(__DATE__), TEXT(__TIME__));

    ssts.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(hssts, &ssts);

    if (!read_registry_key(L"pollEach", &poll_each) || poll_each[0] == '\0') {
        if (poll_each) free(poll_each);
        timeout = 0;
    } else {
        timeout = wcstol(poll_each, NULL, 10);
        if (errno == ERANGE) {
            LOG(LOG_ERROR, L"ServiceMain(): invalid pollEach registry key value. Periodic directory poll is disabled - using default file system event worker");
            timeout = 0;
        }
        free(poll_each);
    }

    if (timeout == 0) {
        LOG(LOG_INFO, L"ServiceMain(): periodic directory poll is disabled - using default file system event worker");
    }

    wrk_thr = CreateThread(NULL, 0,
            (LPTHREAD_START_ROUTINE) (timeout == 0 ? directory_worker : directory_time_worker),
            &timeout, 0, NULL);
    if (!wrk_thr) {
        ssts.dwCurrentState = SERVICE_STOPPED;
        ssts.dwWin32ExitCode = -1;
        SetServiceStatus(hssts, &ssts);
        LOG(LOG_ERROR, L"ServiceMain(): create worker thread failed, error: %d", GetLastError());
    }
    handles[0] = wrk_thr;
    handles[1] = hkill_event;
    handles[2] = hthr_event;
    WaitForMultipleObjects(3, handles, TRUE, INFINITE);
    stop_logger(L"service exit", log_handle);
    WaitForSingleObject(log_thr, INFINITE);
    CloseHandle(wrk_thr);
    CloseHandle(log_thr);
    Sleep(2000);
    queue_delete(log_handle);
}