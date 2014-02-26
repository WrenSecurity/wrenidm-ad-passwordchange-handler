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
 * "Portions Copyrighted [2012] [Forgerock AS]"
 **/

#ifndef __UTILS_H__
#define __UTILS_H__

#include <stdint.h>
#include <process.h>

#define JSON_PAYLOAD \
        L"[{"\
        L" \"operation\" : \"replace\","\
        L" \"field\" : \"/%s\","\
        L" \"value\" :"\
        L"  {"\
        L"   \"$crypto\" :"\
        L"    {"\
        L"     \"value\" :"\
        L"      {"\
        L"       \"data\" : \"%s\","\
        L"       \"cipher\" : \"AES/ECB/PKCS5Padding\","\
        L"       \"key\" :"\
        L"        {"\
        L"         \"data\" : \"%s\","\
        L"         \"cipher\" : \"RSA/ECB/PKCS1Padding\","\
        L"         \"key\" : \"%s\""\
        L"        }"\
        L"      },"\
        L"     \"type\" : \"x-simple-encryption\""\
        L"    }"\
        L"  }"\
        L"}]"

#define IDM_REG_SUBKEY L"SOFTWARE\\ForgeRock\\OpenIDM\\PasswordSync"

typedef enum {
    AES128,
    AES192,
    AES256
} ENCR_KEY_ALG;

void DEBUG_INT(const wchar_t *fmt, ...);
#define DEBUG(fmt, ...) DEBUG_INT(TEXT(fmt), __VA_ARGS__)
void show_windows_error(DWORD err);

int idm_printf(wchar_t **buffer, const wchar_t *fmt, ...);

uint64_t timestamp_id();

wchar_t * timestamp_log();

wchar_t *utf8_decode(const char *str, size_t *outlen);

char *utf8_encode(const wchar_t *wstr, size_t *outlen);

char * base64decodeA(const char *input, size_t length, size_t *outlen);

char *base64encodeA(const char *input, size_t length, size_t *outlen);

wchar_t * base64decode(const wchar_t *input, size_t length, size_t *outlen);

wchar_t * base64encode(const wchar_t *input, size_t length, size_t *outlen);

wchar_t * md5(const wchar_t *plain);

BOOL encrypt(const wchar_t *password, const wchar_t * certf, const wchar_t * certp,
        char ** encrypted, char ** key, ENCR_KEY_ALG alg);

BOOL generate_key(char **b64key, size_t *size);

BOOL encrypt_password(const char *b64key, const char *data, char ** b64encr);

BOOL decrypt_password(const char *b64key, const char *b64data, char ** clear);

void free_list(wchar_t **list, int listsize);

wchar_t * string_replace(const wchar_t *original, const wchar_t *pattern, const wchar_t *replace);

int count_char(const wchar_t *str, wchar_t w);

BOOL create_directory(const wchar_t * dir);

wchar_t ** traverse_directory(const wchar_t * dir, int *count);

BOOL read_registry_key(wchar_t *key, wchar_t **value);

#endif
