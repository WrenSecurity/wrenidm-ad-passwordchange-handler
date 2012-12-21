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

#ifndef __LOG_H__
#define __LOG_H__

#include <windows.h>
#include "utils.h"

typedef enum {
    LOG_NONE,
    LOG_ERROR,
    LOG_WARNING,
    LOG_INFO,
    LOG_DEBUG,
    LOG_FATAL,
    LOG_ALWAYS
} LOG_LEVEL;

typedef struct {
    wchar_t *msg;
    LOG_LEVEL level;
    int quit_flag;
    DWORD tid;
    int pid;
    wchar_t *ts;
} LOG_MESSAGE;

typedef struct {
    void **buffer;
    int capacity;
    int size;
    int in;
    int out;
    CRITICAL_SECTION mutex;
    CONDITION_VARIABLE cond_full;
    CONDITION_VARIABLE cond_empty;
} LOG_QUEUE;

#define LOGNAME L"idm.log"
#define LOGLOCK L"Global\\idm_log_lock"

extern LOG_QUEUE *log_handle;
extern LOG_LEVEL log_level;
extern wchar_t log_path[MAX_PATH];
extern wchar_t log_path_idx[MAX_PATH];

void stop_logger(const wchar_t *, LOG_QUEUE *);
LOG_LEVEL get_log_level();
BOOL set_log_path(wchar_t **);

#define LOG(_level_, ...) do {\
           LOG_MESSAGE *__log_message_ = (LOG_MESSAGE *) malloc(sizeof (LOG_MESSAGE));\
           if (__log_message_ == NULL) {DEBUG("LOG malloc error %d", GetLastError());} else {\
           __log_message_->level = _level_;\
           __log_message_->quit_flag = 0;\
           __log_message_->msg = NULL;\
           __log_message_->tid = GetCurrentThreadId();\
           __log_message_->pid = _getpid();\
           __log_message_->ts = timestamp_log();\
           idm_printf(&(__log_message_->msg), __VA_ARGS__);\
           queue_enqueue(log_handle, __log_message_);}} while (0)

DWORD WINAPI log_worker(void *);

LOG_QUEUE *queue_init(void *);
void queue_delete(LOG_QUEUE *);
void queue_enqueue(LOG_QUEUE *, void *);
void *queue_dequeue(LOG_QUEUE *);
int queue_size(LOG_QUEUE *);

#endif
