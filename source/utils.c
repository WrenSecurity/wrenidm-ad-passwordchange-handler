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
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>
#include <io.h>
#include <sys/types.h> 
#include <sys/timeb.h>
#include "log.h"

char *utf8_encode(const wchar_t *wstr, size_t *outlen) {
    char *tmp = NULL;
    size_t out_len = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (outlen) *outlen = 0;
    if (out_len > 0) {
        tmp = (char *) malloc(out_len);
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, tmp, (DWORD) out_len, NULL, NULL);
        tmp[out_len - 1] = 0;
        if (outlen) *outlen = out_len - 1;
        return tmp;
    }
    return NULL;
}

wchar_t *utf8_decode(const char *str, size_t *outlen) {
    wchar_t *tmp = NULL;
    size_t out_len = MultiByteToWideChar(CP_UTF8, 0, str, -1, NULL, 0);
    if (outlen) *outlen = 0;
    if (out_len > 0) {
        tmp = (wchar_t *) malloc(sizeof (wchar_t) * out_len);
        MultiByteToWideChar(CP_UTF8, 0, str, -1, tmp, (DWORD) out_len);
        tmp[out_len - 1] = 0;
        if (outlen) *outlen = out_len - 1;
        return tmp;
    }
    return NULL;
}

wchar_t * base64decode(const wchar_t *input, size_t length, size_t *outlen) {
    DWORD ulBlobSz = 0, ulSkipped = 0, ulFmt = 0;
    BYTE *tmp = NULL;
    wchar_t *out = NULL;
    if (outlen) *outlen = 0;
    if (input == NULL) return NULL;
    if (CryptStringToBinary(input, (DWORD) length, CRYPT_STRING_BASE64, NULL, &ulBlobSz, &ulSkipped, &ulFmt) == TRUE) {
        if ((tmp = malloc((ulBlobSz + 1) * sizeof (wchar_t))) != NULL) {
            if (CryptStringToBinary(input, (DWORD) length, CRYPT_STRING_BASE64, tmp, &ulBlobSz, &ulSkipped, &ulFmt) == TRUE) {
                tmp[ulBlobSz] = 0;
                out = utf8_decode(tmp, outlen);
            }
            free(tmp);
        }
    }
    return out;
}

wchar_t * base64encode(const wchar_t *input, size_t length, size_t *outlen) {
    wchar_t *buf = NULL;
    char *tmp = NULL;
    DWORD ulEncLen = 0;
    if (outlen) *outlen = 0;
    if (input == NULL) return NULL;
    else if ((tmp = utf8_encode(input, NULL)) == NULL) return NULL;
    if (CryptBinaryToString((const BYTE *) tmp, (DWORD) length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &ulEncLen) == TRUE) {
        if ((buf = (wchar_t *) malloc((ulEncLen + 1) * sizeof (wchar_t))) != NULL) {
            if (CryptBinaryToString((const BYTE *) tmp, (DWORD) length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, buf, &ulEncLen) == TRUE) {
                buf[ulEncLen] = 0;
                if (outlen) *outlen = ulEncLen;
            }
        }
    }
    free(tmp);
    return buf;
}

char * base64decodeA(const char *input, size_t length, size_t *outlen) {
    DWORD ulBlobSz = 0, ulSkipped = 0, ulFmt = 0;
    BYTE *tmp = NULL;
    if (outlen) *outlen = 0;
    if (input == NULL) return NULL;
    if (CryptStringToBinaryA(input, (DWORD) length, CRYPT_STRING_BASE64, NULL, &ulBlobSz, &ulSkipped, &ulFmt) == TRUE) {
        if ((tmp = malloc(ulBlobSz + 1)) != NULL) {
            if (CryptStringToBinaryA(input, (DWORD) length, CRYPT_STRING_BASE64, tmp, &ulBlobSz, &ulSkipped, &ulFmt) == TRUE) {
                tmp[ulBlobSz] = 0;
                if (outlen) *outlen = ulBlobSz;
            }
        }
    }
    return tmp;
}

char * base64encodeA(const char *input, size_t length, size_t *outlen) {
    BYTE *tmp = NULL;
    DWORD ulEncLen = 0;
    if (outlen) *outlen = 0;
    if (input == NULL) return NULL;
    if (CryptBinaryToStringA((const BYTE *) input, (DWORD) length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &ulEncLen) == TRUE) {
        if ((tmp = malloc(ulEncLen + 1)) != NULL) {
            if (CryptBinaryToStringA((const BYTE *) input, (DWORD) length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, tmp, &ulEncLen) == TRUE) {
                tmp[ulEncLen] = 0;
                if (outlen) *outlen = ulEncLen;
            }
        }
    }
    return tmp;
}

#define va_copy(dst, src) ((void)((dst) = (src)))

int vaswprintf(wchar_t **buffer, const wchar_t *fmt, va_list arg) {
    int size;
    va_list ap;
    *buffer = NULL;
    va_copy(ap, arg);
    size = _vsnwprintf(NULL, 0, fmt, ap);
    va_end(ap);
    if (size >= 0) {
        if ((*buffer = malloc(++size * sizeof (wchar_t))) != NULL) {
            if ((size = _vsnwprintf(*buffer, size, fmt, arg)) < 0) {
                free(*buffer);
                *buffer = NULL;
            }
        }
    }
    return size;
}

int idm_printf(wchar_t **buffer, const wchar_t *fmt, ...) {
    int size;
    wchar_t *tmp = NULL;
    va_list ap;
    va_start(ap, fmt);
    tmp = *buffer;
    size = vaswprintf(buffer, fmt, ap);
    if (tmp != NULL) {
        free(tmp);
    }
    va_end(ap);
    return size;
}

uint64_t timestamp_id() {
    SYSTEMTIME lt;
    uint64_t n = 0;
    wchar_t *p, *time = NULL;
    GetLocalTime(&lt);
    if (idm_printf(&time, TEXT("%4d%2d%2d%2d%2d%2d%3d"), lt.wYear, lt.wMonth, lt.wDay,
            lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds) > 0) {
        for (p = time; *p != '\0'; p++) {
            if (iswspace(*p)) *p = '0';
        }
        n = (uint64_t) _wcstoui64(time, NULL, 10);
        free(time);
    }
    return n;
}

wchar_t *timestamp_log() {
    int offset = 0;
    wchar_t time_string_tz[40];
    wchar_t time_string[20];
    struct tm ptmw;
    struct timeb tstruct;
    time_t rawtime;
    ftime(&tstruct);
    rawtime = tstruct.time;
    localtime_s(&ptmw, &rawtime);
    offset = (-(int) timezone);
    if (ptmw.tm_isdst) offset += 3600;
    wcsftime(time_string, sizeof (time_string), L"%Y-%m-%d %H:%M:%S", &ptmw);
    _snwprintf(time_string_tz, sizeof (time_string_tz), L"%s.%03d %+03d%02d", time_string, tstruct.millitm, (int) (offset / 3600),
            (int) ((abs((int) offset) / 60) % 60));
    return _wcsdup(time_string_tz);
}

wchar_t * md5(const wchar_t *plain) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    BYTE bHash[0x7f];
    DWORD i, l = 0, dwHashLen = 16, cbContent = 0;
    char finalhash[33], dig[] = "0123456789ABCDEF";
    char *plain_enc = NULL;
    if (plain != NULL && (plain_enc = utf8_encode(plain, (size_t *) & cbContent)) != NULL) {
        if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET)) {
            if (CryptCreateHash(prov, CALG_MD5, 0, 0, &hash)) {
                if (CryptHashData(hash, plain_enc, cbContent, 0)) {
                    if (CryptGetHashParam(hash, HP_HASHVAL, bHash, &dwHashLen, 0)) {
                        memset(&finalhash[0], 0x00, sizeof (finalhash));
                        for (i = 0; i < 16; i++) {
                            finalhash[l] = dig[bHash[i] >> 4];
                            l++;
                            finalhash[l] = dig[bHash[i] & 0xf];
                            l++;
                        }
                        free(plain_enc);
                        CryptDestroyHash(hash);
                        CryptReleaseContext(prov, 0);
                        finalhash[l] = 0;
                        return utf8_decode(finalhash, NULL);
                    }
                }
                CryptDestroyHash(hash);
            }
            CryptReleaseContext(prov, 0);
        }
        free(plain_enc);
    }
    return NULL;
}

static BOOL encrypt_key(HCRYPTPROV hCryptProv, BYTE * cdata, DWORD cdatasize,
        const wchar_t * certf, const wchar_t * certp, char ** encoded) {
    BOOL ret = FALSE;
    HANDLE hfile = INVALID_HANDLE_VALUE;
    HANDLE hsection = 0;
    void* pfx = 0;
    PCCERT_CONTEXT pContext = 0;
    DWORD dwBufSize = 0;
    CERT_PUBLIC_KEY_INFO* spki = NULL;
    BYTE *blobBuf = NULL;
    HCRYPTKEY key;
    DWORD i, dwKeySize = 0;
    DWORD dwParamSize = sizeof (DWORD);
    DWORD dataLen = cdatasize;
    DWORD sizeSource = cdatasize;
    BYTE *encpww = NULL;
    CRYPT_DATA_BLOB blob;
    HCERTSTORE pfxStore = 0;

    if ((hfile = CreateFile(certf, FILE_READ_DATA, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)) != INVALID_HANDLE_VALUE) {
        if ((hsection = CreateFileMapping(hfile, 0, PAGE_READONLY, 0, 0, 0))) {
            if ((pfx = MapViewOfFile(hsection, FILE_MAP_READ, 0, 0, 0))) {
                blob.cbData = GetFileSize(hfile, 0);
                blob.pbData = (BYTE*) pfx;
                if (PFXIsPFXBlob(&blob)) {
                    if ((pfxStore = PFXImportCertStore(&blob, certp, CRYPT_MACHINE_KEYSET | CRYPT_EXPORTABLE))) {
                        if ((pContext = CertEnumCertificatesInStore(pfxStore, pContext))) {
                            spki = &pContext->pCertInfo->SubjectPublicKeyInfo;
                            if (CryptDecodeObject(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
                                    spki->PublicKey.pbData, spki->PublicKey.cbData, 0, 0, &dwBufSize)) {
                                if ((blobBuf = (BYTE *) calloc(1, dwBufSize)) != NULL) {
                                    if (CryptDecodeObject(X509_ASN_ENCODING, RSA_CSP_PUBLICKEYBLOB,
                                            spki->PublicKey.pbData, spki->PublicKey.cbData, 0, blobBuf, &dwBufSize)) {
                                        if (CryptImportKey(hCryptProv, blobBuf, dwBufSize, 0, 0, &key)) {
                                            if (CryptGetKeyParam(key, KP_KEYLEN, (BYTE*) & dwKeySize, &dwParamSize, 0)) {
                                                if (dwKeySize > 0) {
                                                    dwKeySize /= 8;
                                                    if (CryptEncrypt(key, 0, TRUE, 0, NULL, &dataLen, sizeSource)) {
                                                        if ((encpww = (BYTE *) calloc(1, dataLen)) != NULL) {
                                                            CopyMemory(encpww, cdata, sizeSource);
                                                            if (CryptEncrypt(key, 0, TRUE, 0, encpww, &sizeSource, dataLen)) {
                                                                for (i = 0; i < (dwKeySize / 2); i++) {
                                                                    BYTE c = encpww[i];
                                                                    encpww[i] = encpww[dwKeySize - 1 - i];
                                                                    encpww[dwKeySize - 1 - i] = c;
                                                                }
                                                                if ((*encoded = base64encodeA(encpww, sizeSource, NULL)) != NULL) {
                                                                    ret = TRUE;
                                                                }
                                                            }
                                                            free(encpww);
                                                        }
                                                    }
                                                }
                                            }
                                            CryptDestroyKey(key);
                                        }
                                    }
                                    free(blobBuf);
                                }
                            }
                            CertFreeCertificateContext(pContext);
                        }
                        CertCloseStore(pfxStore, CERT_CLOSE_STORE_FORCE_FLAG);
                    }
                }
                UnmapViewOfFile(pfx);
            }
            CloseHandle(hsection);
        }
        CloseHandle(hfile);
    }
    return ret;
}

BOOL encrypt(const wchar_t *password, const wchar_t * certf, const wchar_t * certp,
        char ** encrypted, char ** key, ENCR_KEY_ALG alg) {
    BOOL ret = FALSE;
    HCRYPTPROV hProv;
    HCRYPTKEY hKey = 0;
    BYTE *pbKeyBlob = NULL, *pbKeyBlobTemp = NULL, *buffTemp = NULL;
    DWORD dwBlobLen, dwBlobLenTemp, sizeDest, sizeSource = 0;
    DWORD dwMode = CRYPT_MODE_ECB;
    DWORD dwPadding = PKCS5_PADDING;
    ALG_ID algid = CALG_AES_128;
    char *password_utf8 = NULL;

    if (password == NULL || certf == NULL || certp == NULL) {
        LOG(LOG_ERROR, L"%s: invalid parameters");
        return FALSE;
    } else {
        password_utf8 = utf8_encode(password, (size_t *) & sizeSource);
        sizeDest = sizeSource;
    }

    switch (alg) {
        case AES256:
            algid = CALG_AES_256;
            break;
        case AES192:
            algid = CALG_AES_192;
            break;
        case AES128:
            algid = CALG_AES_128;
            break;
    }

    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptGenKey(hProv, algid, CRYPT_EXPORTABLE, &hKey)) {
            if (CryptSetKeyParam(hKey, KP_PADDING, (PBYTE) & dwPadding, 0)
                    && CryptSetKeyParam(hKey, KP_MODE, (PBYTE) & dwMode, 0)) {
                if (CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &dwBlobLenTemp)) {
                    if ((pbKeyBlobTemp = (BYTE*) calloc(1, dwBlobLenTemp)) != NULL) {
                        if (CryptExportKey(hKey, 0, PLAINTEXTKEYBLOB, 0, pbKeyBlobTemp, &dwBlobLenTemp)) {
                            dwBlobLen = dwBlobLenTemp - 12;
                            if ((pbKeyBlob = (BYTE*) calloc(1, dwBlobLen)) != NULL) {
                                CopyMemory(pbKeyBlob, pbKeyBlobTemp + 12, dwBlobLen);
                                if (CryptEncrypt(hKey, 0, TRUE, 0, NULL, &sizeDest, sizeSource)) {
                                    if ((buffTemp = (BYTE *) calloc(1, sizeDest)) != NULL) {
                                        CopyMemory(buffTemp, password_utf8, sizeSource);
                                        if (CryptEncrypt(hKey, 0, TRUE, 0, buffTemp, &sizeSource, sizeDest)) {
                                            if ((*encrypted = base64encodeA(buffTemp, sizeSource, NULL)) != NULL) {
                                                ret = encrypt_key(hProv, pbKeyBlob, dwBlobLen, certf, certp, key);
                                            }
                                        }
                                        free(buffTemp);
                                    }
                                }
                                free(pbKeyBlob);
                            }
                        }
                        free(pbKeyBlobTemp);
                    }
                }
            }
            CryptDestroyKey(hKey);
        }
        CryptReleaseContext(hProv, 0);
    }
    if (password_utf8) free(password_utf8);
    return ret;
}

void free_list(wchar_t **list, int listsize) {
    int i;
    if (list != NULL) {
        for (i = 0; i < listsize; i++) {
            if (list[i] != NULL) free(list[i]);
        }
        free(list);
    }
}

static int count_files(const wchar_t * filespec) {
    int count = 0;
    struct _wfinddata_t data;
    intptr_t h;
    if (filespec != NULL) {
        if ((h = _wfindfirst(filespec, &data)) > -1) {
            do {
                if (!(data.attrib & _A_SUBDIR)) count++;
            } while (_wfindnext(h, &data) == 0);
            _findclose(h);
        }
    }
    return count;
}

static int compare_files(const void * a, const void * b) {
    return wcscoll((wchar_t *) b, (wchar_t *) a);
}

wchar_t ** traverse_directory(const wchar_t * dir, int *count) {
    struct _wfinddata_t data;
    int i = 0;
    intptr_t h;
    wchar_t ** list = NULL;
    wchar_t * filespec = NULL;
    if (dir != NULL) {
        idm_printf(&filespec, L"%s/*.json", dir);
        if (filespec != NULL) {
            if ((*count = count_files(filespec)) > 0) {
                list = (wchar_t **) malloc((*count) * sizeof (wchar_t *));
                if (list != NULL && (h = _wfindfirst(filespec, &data)) > -1) {
                    do {
                        if (!(data.attrib & _A_SUBDIR)) {
                            list[i] = NULL;
                            idm_printf(&(list[i]), L"%s/%s", dir, data.name);
                            i++;
                        }
                    } while (_wfindnext(h, &data) == 0);
                    _findclose(h);
                    if (i > 0) qsort(list, i, sizeof (list[0]), compare_files);
                }
            }
            free(filespec);
        }
    }
    return list;
}

BOOL create_directory(const wchar_t *path) {
    wchar_t *p = NULL;
    BOOL b = FALSE;
    if (!(b = CreateDirectory(path, NULL))
            && !(b = NULL == (p = wcsrchr(path, '/')))) {
        size_t i;
        (p = wcsncpy((wchar_t *) malloc(i * sizeof (wchar_t) + 2),
                path, i = p - path))[i] = '\0';
        b = create_directory(p);
        free(p);
        b = b ? (CreateDirectory(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) : FALSE;
    }
    return b;
}

void DEBUG_INT(const wchar_t *fmt, ...) {
    va_list ap;
    int bsize = 0;
    wchar_t *buf = NULL;
    va_start(ap, fmt);
    bsize = vaswprintf(&buf, fmt, ap);
    va_end(ap);
    if (buf != NULL) {
        buf[bsize] = 0;
        OutputDebugString(buf);
        OutputDebugString(TEXT("\n"));
        free(buf);
    }
}

void show_windows_error(DWORD err) {
    LPVOID e = NULL;
    if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            NULL, err, 0,
            (LPTSTR) & e, 0, NULL) != 0) {
        fwprintf(stderr, L"%s (error: %d)\n", e, err);
        OutputDebugString(e);
        OutputDebugString(L"\n");
    }
    if (e) {
        LocalFree(e);
    }
}

BOOL read_registry_key(wchar_t *key, wchar_t **value) {
    HRESULT hr = S_OK;
    DWORD cbDataSize = 1024;
    *value = NULL;
    if (!(*value = (LPWSTR) malloc(cbDataSize))) {
        return FALSE;
    } else {
        **value = L'\0';
    }
    while (S_OK == hr && S_OK != (hr = HRESULT_FROM_WIN32(
            RegGetValue(HKEY_LOCAL_MACHINE, IDM_REG_SUBKEY, key, RRF_RT_ANY,
            NULL, *value, &cbDataSize)))) {
        if (*value) {
            free(*value);
            *value = NULL;
        }
        if (HRESULT_FROM_WIN32(ERROR_MORE_DATA) == hr) {
            hr = S_OK;
            if (!(*value = (LPWSTR) malloc(cbDataSize))) {
                hr = E_OUTOFMEMORY;
            }
        } else {
            break;
        }
    }
    if (S_OK != hr && *value) {
        free(*value);
        *value = NULL;
    }
    return hr == S_OK ? TRUE : FALSE;
}

int count_char(const wchar_t *a, wchar_t w) {
    int count = 0;
    const wchar_t *b = a;
    if (b)
        while (*b) if (*b++ == w) ++count;
    return count;
}

wchar_t * string_replace(const wchar_t *original, const wchar_t *pattern, const wchar_t *replace) {
    size_t pcnt = 0;
    const wchar_t * optr;
    const wchar_t * ploc;
    if (original != NULL && pattern != NULL && replace != NULL) {
        size_t rlen = wcslen(replace);
        size_t plen = wcslen(pattern);
        size_t olen = wcslen(original);
        for (optr = original; ploc = wcsstr(optr, pattern); optr = ploc + plen) pcnt++;
        if (pcnt > 0) {
            size_t retlen = olen + pcnt * (rlen - plen);
            wchar_t *returned = (wchar_t *) malloc(sizeof (wchar_t) * (retlen + 1));
            if (returned != NULL) {
                wchar_t * retptr = returned;
                for (optr = original; ploc = wcsstr(optr, pattern); optr = ploc + plen) {
                    size_t slen = ploc - optr;
                    wcsncpy(retptr, optr, slen);
                    retptr += slen;
                    wcsncpy(retptr, replace, rlen);
                    retptr += rlen;
                }
                wcscpy(retptr, optr);
            }
            return returned;
        }
    }
    return NULL;
}

BOOL generate_key(char **b64key, size_t *size) {
    HCRYPTPROV prov;
    HCRYPTKEY key = 0;
    BOOL ret = FALSE;
    BYTE *blob = NULL;
    DWORD blob_size;
    DWORD mode = CRYPT_MODE_CBC;
    DWORD pad = PKCS5_PADDING;
    BYTE IV[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptGenKey(prov, CALG_AES_256, CRYPT_EXPORTABLE, &key)) {
            if (CryptSetKeyParam(key, KP_PADDING, (PBYTE) & pad, 0)
                    && CryptSetKeyParam(key, KP_MODE, (PBYTE) & mode, 0)) {
                CryptSetKeyParam(key, KP_IV, &IV[0], 0);
                if (CryptExportKey(key, 0, PLAINTEXTKEYBLOB, 0, NULL, &blob_size)) {
                    if ((blob = (BYTE*) calloc(1, blob_size)) != NULL) {
                        if (CryptExportKey(key, 0, PLAINTEXTKEYBLOB, 0, blob, &blob_size)) {
                            *b64key = base64encodeA(blob + 12, (size_t) blob_size - 12, size);
                            if (*b64key) ret = TRUE;
                        }
                        free(blob);
                    }
                }
            }
            CryptDestroyKey(key);
        }
        CryptReleaseContext(prov, 0);
    }
    return ret;
}

BOOL encrypt_password(const char *b64key, const char *data, char ** b64encr) {
    HCRYPTPROV prov;
    HCRYPTKEY key;
    BYTE IV[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    DWORD mode = CRYPT_MODE_CBC, padding = PKCS5_PADDING, count = 32, buf_size, pad, offset;
    PBYTE in = NULL, out = NULL, key_blob = NULL;
    BOOL status = FALSE;

    struct akb {
        BLOBHEADER hdr;
        DWORD keySize;
        BYTE bytes[32];
    } blob;

    if (b64key != NULL
            && (key_blob = base64decodeA(b64key, strlen(b64key), NULL)) != NULL) {
        blob.hdr.bType = PLAINTEXTKEYBLOB;
        blob.hdr.bVersion = CUR_BLOB_VERSION;
        blob.hdr.reserved = 0;
        blob.hdr.aiKeyAlg = CALG_AES_256;
        blob.keySize = 32;
        memcpy(blob.bytes, key_blob, 32);
        free(key_blob);
    }

    if (data != NULL) {
        if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
            if (CryptImportKey(prov, (BYTE*) & blob, sizeof (blob), 0, 0, &key)) {
                DWORD data_size = (DWORD) strlen(data);
                CryptSetKeyParam(key, KP_MODE, (BYTE*) & mode, 0);
                CryptSetKeyParam(key, KP_PADDING, (BYTE*) & padding, 0);
                CryptSetKeyParam(key, KP_IV, &IV[0], 0);
                pad = 32 - (data_size % 32);
                buf_size = data_size + pad + 32;
                in = (BYTE *) malloc(buf_size);
                if (in != NULL) {
                    out = (BYTE *) malloc(buf_size);
                    if (out != NULL) {
                        memcpy(in, data, data_size);
                        for (offset = 0; offset < buf_size; offset += 32) {
                            if ((offset + 32) >= buf_size) status = TRUE;
                            if (CryptEncrypt(key, (HCRYPTHASH) NULL, status, 0, in + offset, &count, 32)) {
                                memcpy(out + offset, in + offset, count);
                            }
                        }
                        *b64encr = base64encodeA(out, buf_size, NULL);
                        free(out);
                    }
                    free(in);
                }
                CryptDestroyKey(key);
            }
            CryptReleaseContext(prov, 0);
        }
    }
    return status;
}

BOOL decrypt_password(const char *b64key, const char *b64data, char ** clear) {
    HCRYPTPROV prov;
    HCRYPTKEY key;
    BYTE IV[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    DWORD mode = CRYPT_MODE_CBC, padding = PKCS5_PADDING, count = 32, offset;
    PBYTE in = NULL, out = NULL, pl = NULL, key_blob = NULL;
    BOOL status = FALSE;
    size_t data_size;

    struct akb {
        BLOBHEADER hdr;
        DWORD keySize;
        BYTE bytes[32];
    } blob;

    if (b64key != NULL
            && (key_blob = base64decodeA(b64key, strlen(b64key), NULL)) != NULL) {
        blob.hdr.bType = PLAINTEXTKEYBLOB;
        blob.hdr.bVersion = CUR_BLOB_VERSION;
        blob.hdr.reserved = 0;
        blob.hdr.aiKeyAlg = CALG_AES_256;
        blob.keySize = 32;
        memcpy(blob.bytes, key_blob, 32);
        free(key_blob);
    }

    if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        if (CryptImportKey(prov, (BYTE*) & blob, sizeof (blob), 0, 0, &key)) {
            CryptSetKeyParam(key, KP_MODE, (BYTE*) & mode, 0);
            CryptSetKeyParam(key, KP_PADDING, (BYTE*) & padding, 0);
            CryptSetKeyParam(key, KP_IV, &IV[0], 0);
            in = b64data != NULL ?
                    base64decodeA(b64data, strlen(b64data), &data_size) : NULL;
            if (in != NULL) {
                out = (BYTE *) malloc(data_size);
                if (out != NULL) {
                    for (offset = 0; offset < data_size; offset += 32) {
                        if ((offset + 32) >= data_size) status = TRUE;
                        if (CryptDecrypt(key, 0, status, 0, in + offset, &count)) {
                            memcpy(out + offset, in + offset, count);
                        }
                    }
                    pl = (BYTE *) memchr(out, 0xCD, data_size);
                    if (pl != NULL) {
                        offset = pl - out;
                        out = (BYTE *) realloc(out, offset + 1);
                        out[offset] = '\0';
                    } else {
                        out[data_size] = '\0';
                    }
                    *clear = out;
                }
                free(in);
            }
            CryptDestroyKey(key);
        }
        CryptReleaseContext(prov, 0);
    }
    return status;
}
