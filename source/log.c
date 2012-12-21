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

#include <stdio.h>
#include <process.h>
#include <io.h>
#include <sys/types.h>
#include "log.h"

#define MAX_FSIZE 5120000 //5Mb

void stop_logger(const wchar_t *msg, LOG_QUEUE *q) {
    if (q != NULL) {
        LOG_MESSAGE *qm = (LOG_MESSAGE *) malloc(sizeof (LOG_MESSAGE));
        if (qm == NULL) {
            DEBUG("stop_logger() malloc error %d", GetLastError());
            return;
        }
        qm->level = LOG_ALWAYS;
        qm->quit_flag = 1;
        qm->tid = GetCurrentThreadId();
        qm->pid = _getpid();
        qm->ts = timestamp_log();
        qm->msg = _wcsdup(msg == NULL ? L"logger exiting" : msg);
        queue_enqueue(q, qm);
    }
}

static void rotate_log(HANDLE file) {
    BY_HANDLE_FILE_INFORMATION info;
    wchar_t tmp[MAX_PATH];
    off_t fsize = 0;
    if (GetFileInformationByHandle(file, &info)) {
        fsize = info.nFileSizeHigh;
        fsize <<= 32;
        fsize += info.nFileSizeLow;
    }
    if (fsize > MAX_FSIZE) {
        unsigned int idx = 1;
        do {
            ZeroMemory(&tmp[0], sizeof (tmp));
            swprintf_s(tmp, sizeof (tmp), log_path_idx, idx);
            idx++;
        } while (_waccess(tmp, 0) >= 0);
        if (CopyFile(log_path, tmp, FALSE)) {
            SetFilePointer(file, 0, NULL, FILE_BEGIN);
            SetEndOfFile(file);
        } else {
            DEBUG("could not copy OpenIDM log file, error: %d", GetLastError());
        }
    }
}

void queue_enqueue(LOG_QUEUE *que, void * value) {
    if (que != NULL) {
        EnterCriticalSection(&(que->mutex));
        while (que->size == que->capacity) {
            SleepConditionVariableCS(&(que->cond_full), &(que->mutex), INFINITE);
        }
        que->buffer[que->in] = value;
        ++(que->size);
        ++(que->in);
        que->in %= que->capacity;
        LeaveCriticalSection(&(que->mutex));
        WakeConditionVariable(&(que->cond_empty));
    }
}

void *queue_dequeue(LOG_QUEUE *que) {
    void *value = NULL;
    if (que != NULL) {
        EnterCriticalSection(&(que->mutex));
        while (que->size == 0) {
            SleepConditionVariableCS(&(que->cond_empty), &(que->mutex), INFINITE);
        }
        value = que->buffer[que->out];
        --(que->size);
        ++(que->out);
        que->out %= que->capacity;
        LeaveCriticalSection(&(que->mutex));
        WakeConditionVariable(&(que->cond_full));
    }
    return value;
}

int queue_size(LOG_QUEUE *que) {
    int size = 0;
    if (que != NULL) {
        EnterCriticalSection(&(que->mutex));
        size = que->size;
        LeaveCriticalSection(&(que->mutex));
    }
    return size;
}

LOG_QUEUE *queue_init(void * buffer) {
    LOG_QUEUE *q = (LOG_QUEUE *) malloc(sizeof (LOG_QUEUE));
    if (q == NULL) {
        DEBUG("queue_init() malloc error %d", GetLastError());
        return NULL;
    }
    q->buffer = buffer;
    q->capacity = sizeof (buffer);
    q->size = 0;
    q->in = 0;
    q->out = 0;
    InitializeCriticalSection(&(q->mutex));
    InitializeConditionVariable(&(q->cond_empty));
    InitializeConditionVariable(&(q->cond_full));
    return q;
}

void queue_delete(LOG_QUEUE *q) {
    if (q != NULL) {
        DeleteCriticalSection(&(q->mutex));
        free(q);
        q = NULL;
    }
}

DWORD WINAPI log_worker(void * p) {
    HANDLE file = INVALID_HANDLE_VALUE, mtx = NULL;
    LOG_QUEUE *log = (LOG_QUEUE *) p;
    wchar_t lvls[32], *msg = NULL;
    DWORD written, pos, msg_size = 0;
    if (log != NULL) {
        mtx = CreateMutex(NULL, FALSE, LOGLOCK);
        if (mtx == NULL && GetLastError() == ERROR_ACCESS_DENIED) {
            mtx = OpenMutex(SYNCHRONIZE, FALSE, LOGLOCK);
        }
        if (mtx != NULL) {
            for (;;) {
                LOG_MESSAGE *qlms = (LOG_MESSAGE *) queue_dequeue(log);
                if (file == INVALID_HANDLE_VALUE) {
                    file = CreateFile(log_path, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                            NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                }
                /*rotate log file*/
                if (WaitForSingleObject(mtx, INFINITE) == WAIT_OBJECT_0) {
                    rotate_log(file);
                    ReleaseMutex(mtx);
                }
                /* check logging level */
                /*
                 * DEBUG < INFO < WARN < ERROR < FATAL
                 */
                if (!((log_level == LOG_NONE && qlms->level != LOG_ALWAYS)
                        || (log_level == LOG_FATAL && qlms->level != LOG_FATAL && qlms->level != LOG_ALWAYS)
                        || (log_level == LOG_ERROR && qlms->level != LOG_FATAL && qlms->level != LOG_ERROR && qlms->level != LOG_ALWAYS)
                        || (log_level == LOG_WARNING && qlms->level != LOG_FATAL && qlms->level != LOG_ERROR && qlms->level != LOG_WARNING && qlms->level != LOG_ALWAYS)
                        || (log_level == LOG_INFO && qlms->level != LOG_FATAL && qlms->level != LOG_ERROR && qlms->level != LOG_WARNING && qlms->level != LOG_INFO && qlms->level != LOG_ALWAYS)
                        )) {
                    switch (qlms->level) {
                        case LOG_ERROR:
                            wcscpy(lvls, L"   ERROR ");
                            break;
                        case LOG_WARNING:
                            wcscpy(lvls, L" WARNING ");
                            break;
                        case LOG_INFO:
                            wcscpy(lvls, L"    INFO ");
                            break;
                        case LOG_DEBUG:
                            wcscpy(lvls, L"   DEBUG ");
                            break;
                        case LOG_FATAL:
                            wcscpy(lvls, L"   FATAL ");
                            break;
                        case LOG_ALWAYS:
                            wcscpy(lvls, L"         ");
                            break;
                    }
                    /*save formatted message to a file*/
                    msg_size = idm_printf(&msg, L"%s%s[%d:%d]  %s\r\n", qlms->ts, lvls, qlms->pid, qlms->tid, (qlms->msg != NULL ? qlms->msg : L"(null)"));
                    if ((pos = SetFilePointer(file, 0, NULL, FILE_END)) != INVALID_SET_FILE_POINTER) {
                        msg_size = (msg_size * sizeof (wchar_t));
                        if (LockFile(file, pos, 0, msg_size, 0)) {
                            if (!WriteFile(file, (LPVOID) msg, msg_size, &written, NULL)) {
                                DEBUG("OpenIDM log file write failed, error: %d", GetLastError());
                            }
                            FlushFileBuffers(file);
                            UnlockFile(file, pos, 0, msg_size, 0);
                        }
                    }
                    if (msg != NULL) {
                        free(msg);
                    }
                    msg = NULL;
                }
                if (qlms != NULL && qlms->msg != NULL) {
                    free(qlms->msg);
                }
                if (qlms != NULL && qlms->ts != NULL) {
                    free(qlms->ts);
                }
                if (qlms->quit_flag == 1) {
                    free(qlms);
                    break;
                }
                free(qlms);
                qlms = NULL;
            }
        } else {
            DEBUG("OpenIDM log create mutex failed, error: %d", GetLastError());
        }
    }
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }
    if (mtx != NULL) {
        CloseHandle(mtx);
    }
    return 0;
}

LOG_LEVEL get_log_level() {
    wchar_t *loglevel = NULL;
    LOG_LEVEL level = LOG_ERROR;
    if (read_registry_key(L"logLevel", &loglevel)) {
        if (wcsicmp(loglevel, L"debug") == 0) {
            level = LOG_DEBUG;
        } else if (wcsicmp(loglevel, L"info") == 0) {
            level = LOG_INFO;
        } else if (wcsicmp(loglevel, L"warning") == 0) {
            level = LOG_WARNING;
        } else if (wcsicmp(loglevel, L"error") == 0) {
            level = LOG_ERROR;
        } else if (wcsicmp(loglevel, L"fatal") == 0) {
            level = LOG_FATAL;
        }
        free(loglevel);
    }
    return level;
}

BOOL set_log_path(wchar_t ** path) {
    BOOL status = FALSE;
    wchar_t log_dir_tmp[MAX_PATH];
    if (!read_registry_key(L"logPath", path) || (*path)[0] == '\0') {
        if (GetTempPath(MAX_PATH, log_dir_tmp)) {
            DEBUG("unable to read logPath registry key, using %s for log files", log_dir_tmp);
            if (*path) free(*path);
            if ((*path = _wcsdup(log_dir_tmp)) != NULL) {
                status = TRUE;
            }
        } else {
            DEBUG("GetTempPath error: %d", GetLastError());
        }
    } else status = TRUE;
    return status;
}
