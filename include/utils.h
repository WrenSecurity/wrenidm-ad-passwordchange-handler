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
 **/

#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdint.h>
#include <process.h>

#define JSON_PAYLOAD \
        "[{"\
        " \"operation\" : \"replace\","\
        " \"field\" : \"/%s\","\
        " \"value\" :"\
        "  {"\
        "   \"$crypto\" :"\
        "    {"\
        "     \"value\" :"\
        "      {"\
        "       \"data\" : \"%s\","\
        "       \"cipher\" : \"AES/ECB/PKCS5Padding\","\
        "       \"key\" :"\
        "        {"\
        "         \"data\" : \"%s\","\
        "         \"cipher\" : \"RSA/ECB/PKCS1Padding\","\
        "         \"key\" : \"%s\""\
        "        }"\
        "      },"\
        "     \"type\" : \"x-simple-encryption\""\
        "    }"\
        "  }"\
        "}]"

#define IDM_REG_SUBKEY "SOFTWARE\\ForgeRock\\OpenIDM\\PasswordSync"

#define DEBUG(fmt, ...)                 _DEBUG_(fmt, __VA_ARGS__)

#define EMPTY                           "(empty)"
#define LOGEMPTY(x)                     (x==NULL ? EMPTY : x)
#define NOTNULL(x)                      (x==NULL ? "" : x)
#define ISVALID(x)                      (x!=NULL && x[0] != '\0')

typedef CRITICAL_SECTION MUTEX;

#define MUTEX_CREATE(m)                 InitializeCriticalSection(&(m))
#define MUTEX_DELETE(m)                 DeleteCriticalSection(&(m))
#define MUTEX_LOCK(m)                   EnterCriticalSection(&(m))
#define MUTEX_UNLOCK(m)                 LeaveCriticalSection(&(m))
#define MUTEX_TRYLOCK(m)                (TryEnterCriticalSection(&(m)) != FALSE)

#define THREAD                          HANDLE
#define THREAD_ID                       GetCurrentThreadId
#define THREAD_WAIT(t)                  WaitForSingleObject(t, INFINITE)
#define THREAD_CREATE(t,f,a)            ((t = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)f, a, 0, NULL)) == NULL ? -1 : 0)

typedef enum {
    AES128,
    AES192,
    AES256
} ENCR_KEY_ALG;

enum {
    SIGNAL = 0,
    BROADCAST = 1,
    MAX = 2
};

typedef struct {
    DWORD c;
    CRITICAL_SECTION d;
    HANDLE e[MAX];
} CONDVAR;

#define CONDVAR_CREATE(m) do {\
        MUTEX_CREATE(m.d);\
        m.e[SIGNAL] = CreateEvent(NULL, FALSE, FALSE, NULL);\
        m.e[BROADCAST] = CreateEvent(NULL, TRUE, FALSE, NULL);\
        m.c = 0;}while(0) 

#define CONDVAR_DELETE(m) do {\
        ResetEvent(m.e[BROADCAST]);\
        CloseHandle(m.e[SIGNAL]);\
        CloseHandle(m.e[BROADCAST]);\
        MUTEX_DELETE(m.d);}while(0) 

#define CONDVAR_SIGNAL(m) do{\
        BOOL w;\
        MUTEX_LOCK(m.d);\
        w = m.c > 0;\
        MUTEX_UNLOCK(m.d);\
        if (w) SetEvent(m.e[SIGNAL]);}while(0)

#define CONDVAR_SIGNAL_ALL(m) do{\
        BOOL w;\
        MUTEX_LOCK(m.d);\
        w = m.c > 0;\
        MUTEX_UNLOCK(m.d);\
        if (w) SetEvent(m.e[BROADCAST]);}while(0)

/*m - CONDVAR; x - MUTEX; t - timeout in msec or INFINITE*/
#define CONDVAR_WAIT(m,x,t) do{\
        DWORD r;BOOL l;\
        MUTEX_LOCK(m.d);\
        m.c++;\
        MUTEX_UNLOCK(m.d);\
        MUTEX_UNLOCK(x);\
        r = WaitForMultipleObjects(2, m.e, FALSE, t);\
        MUTEX_LOCK(m.d);\
        m.c--;\
        l = r == WAIT_OBJECT_0 + BROADCAST && m.c == 0;\
        MUTEX_UNLOCK(m.d);\
        if (l) ResetEvent(m.e[BROADCAST]);\
        MUTEX_LOCK(x);}while(0)



int asprintf(char **buffer, const char *fmt, ...);
size_t write_file(const char *fn, const char *data, size_t size);

uint64_t timestamp_id();
char *timestamp_log();
uint64_t max_log_size();

char * md5(const char *plain, size_t len);
char * base64_encode(const char *input, size_t length, size_t *outlen);
char * base64_decode(const char *input, size_t length, size_t *outlen);

BOOL read_registry_key(const char *key, char **value);
void _DEBUG_(const char *fmt, ...);
void show_windows_error(DWORD err);
BOOL create_directory(const char *path);
char ** traverse_directory(const char * dir, int *count);
void free_list(char **list, int listsize);

int count_char(const char *a, char w);
char * string_replace(const char *original, const char *pattern, const char *replace);

char *utf8_encode(const wchar_t *wstr, size_t *outlen);
wchar_t *utf8_decode(const char *str, size_t *outlen);
char * base64_decode(const char *input, size_t length, size_t *outlen);
char * base64_encode(const char *input, size_t length, size_t *outlen);

BOOL generate_key(char **b64key, size_t *size);
BOOL encrypt_password(const char *b64key, const char *data, char ** b64encr);
BOOL encrypt(const char *password, size_t pass_len, const char * certf, const char * certp,
        char ** encrypted, char ** key, ENCR_KEY_ALG alg);

void log_info(void *, const char *format, ...);
void log_warning(void *, const char *format, ...);
void log_error(void *, const char *format, ...);
void log_debug(void *, const char *format, ...);

#endif
