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

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <assert.h>
#include <time.h>
#include <io.h>
#include <errno.h>
#include <sys/types.h> 
#include "utils.h"
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

char * base64_decode(const char *input, size_t length, size_t *outlen) {
    DWORD ulBlobSz = 0, ulSkipped = 0, ulFmt = 0;
    BYTE *tmp = NULL;
    if (outlen) *outlen = 0;
    if (input == NULL) return NULL;
    if (CryptStringToBinaryA(input, (DWORD) length, CRYPT_STRING_BASE64, NULL, &ulBlobSz, &ulSkipped, &ulFmt) == TRUE) {
        if ((tmp = malloc(ulBlobSz + 1)) != NULL) {
            memset(tmp, 0x00, ulBlobSz + 1);
            if (CryptStringToBinaryA(input, (DWORD) length, CRYPT_STRING_BASE64, tmp, &ulBlobSz, &ulSkipped, &ulFmt) == TRUE) {
                tmp[ulBlobSz] = 0;
                if (outlen) *outlen = ulBlobSz;
            }
        }
    }
    return tmp;
}

static void trimcrlf(LPSTR pszSrcString) {
    LPSTR pszDestString = pszSrcString;
    while (*pszSrcString) {
        if (*pszSrcString == 0x0D) {
            pszSrcString++;
            pszSrcString++;
        } else {
            *pszDestString = *pszSrcString;
            pszDestString++;
            pszSrcString++;
        }
    }
    *pszDestString = *pszSrcString;
}

char * base64_encode(const char *input, size_t length, size_t *outlen) {
    BYTE *tmp = NULL;
    DWORD ulEncLen = 0;
    if (outlen) *outlen = 0;
    if (input == NULL) return NULL;
    if (CryptBinaryToStringA((const BYTE *) input, (DWORD) length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &ulEncLen) == TRUE) {
        if ((tmp = malloc(ulEncLen + 1)) != NULL) {
            memset(tmp, 0x00, ulEncLen + 1);
            if (CryptBinaryToStringA((const BYTE *) input, (DWORD) length, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, tmp, &ulEncLen) == TRUE) {
                tmp[ulEncLen] = 0;
                trimcrlf(tmp);
                if (outlen) *outlen = ulEncLen;
            }
        }
    }
    return tmp;
}

#if (_MSC_VER < 1800)
#define va_copy(dst, src) ((void)((dst) = (src)))
#endif

static int vasprintf(char **buffer, const char *fmt, va_list arg) {
    int size;
    va_list ap;
    *buffer = NULL;
    va_copy(ap, arg);
    size = _vsnprintf(NULL, 0, fmt, ap);
    if (size >= 0) {
        if ((*buffer = malloc(++size)) != NULL) {
            va_end(ap);
            va_copy(ap, arg);
            if ((size = _vsnprintf(*buffer, size, fmt, ap)) < 0) {
                free(*buffer);
                *buffer = NULL;
            }
        }
    }
    va_end(ap);
    return size;
}

int asprintf(char **buffer, const char *fmt, ...) {
    int size;
    char *tmp = NULL;
    va_list ap;
    va_start(ap, fmt);
    tmp = *buffer;
    size = vasprintf(buffer, fmt, ap);
    free(tmp);
    va_end(ap);
    return size;
}

size_t write_file(const char *fn, const char *data, size_t size) {
    size_t w = 0;
    FILE *file = fopen(fn, "wb");
    if (file != NULL) {
        w = fwrite(data, 1, size, file);
        fclose(file);
    }
    return w;
}

uint64_t timestamp_id() {
    SYSTEMTIME lt;
    uint64_t n = 0;
    char time[18];
    GetLocalTime(&lt);
    if (_snprintf(time, sizeof (time), "%04d%02d%02d%02d%02d%02d%03d", lt.wYear, lt.wMonth, lt.wDay,
            lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds) > 0) {
        n = (uint64_t) _strtoui64(time, NULL, 10);
    }
    return n;
}

char *timestamp_log() {
    TIME_ZONE_INFORMATION tz;
    int minutes;
    SYSTEMTIME st;
    char time_string[50];
    char tme[20];
    char tze[6];
    GetLocalTime(&st);
    GetTimeZoneInformation(&tz);
    GetTimeFormatA(LOCALE_USER_DEFAULT, TIME_NOTIMEMARKER | TIME_FORCE24HOURFORMAT, &st,
            "HH':'mm':'ss", tme, sizeof (tme));
    minutes = -(tz.Bias);
    _snprintf(tze, sizeof (tze), "%03d%02d", minutes / 60, abs(minutes % 60));
    if (*tze == '0') {
        *tze = '+';
    }
    _snprintf(time_string, sizeof (time_string), "%04d-%02d-%02d %s.%03d %s", st.wYear, st.wMonth, st.wDay,
            tme, st.wMilliseconds, tze);
    return strdup(time_string);
}

char *md5(const char *plain, size_t len) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    BYTE bHash[0x7f];
    DWORD i, l = 0, dwHashLen = 16, cbContent = (DWORD) len;
    char finalhash[33], dig[] = "0123456789ABCDEF";
    if (plain != NULL) {
        if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_MACHINE_KEYSET)) {
            if (CryptCreateHash(prov, CALG_MD5, 0, 0, &hash)) {
                if (CryptHashData(hash, plain, cbContent, 0)) {
                    if (CryptGetHashParam(hash, HP_HASHVAL, bHash, &dwHashLen, 0)) {
                        memset(&finalhash[0], 0x00, sizeof (finalhash));
                        for (i = 0; i < 16; i++) {
                            finalhash[l] = dig[bHash[i] >> 4];
                            l++;
                            finalhash[l] = dig[bHash[i] & 0xf];
                            l++;
                        }
                        CryptDestroyHash(hash);
                        CryptReleaseContext(prov, 0);
                        finalhash[l] = 0;
                        return strdup(finalhash);
                    }
                }
                CryptDestroyHash(hash);
            }
            CryptReleaseContext(prov, 0);
        }
    }
    return NULL;
}

void _DEBUG_(const char *fmt, ...) {
    va_list ap;
    char *buf = NULL;
    va_start(ap, fmt);
    vasprintf(&buf, fmt, ap);
    va_end(ap);
    if (buf != NULL) {
        OutputDebugString(buf);
        OutputDebugString("\n");
        free(buf);
    }
}

void show_windows_error(DWORD err) {
    LPVOID e = NULL;
    if (FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
            NULL, err, 0,
            (LPTSTR) & e, 0, NULL) != 0) {
        fprintf(stderr, "%s (error: %d)\n", e, err);
        OutputDebugString(e);
        OutputDebugString("\n");
    }
    if (e) {
        LocalFree(e);
    }
}

BOOL read_registry_key(const char *key, char **value) {
    HRESULT hr = S_OK;
    DWORD cbDataSize = 1024;
    *value = NULL;
    if (!(*value = (char *) malloc(cbDataSize))) {
        return FALSE;
    } else {
        **value = '\0';
    }
    while (S_OK == hr && S_OK != (hr = HRESULT_FROM_WIN32(RegGetValueA(HKEY_LOCAL_MACHINE,
            (LPCTSTR) IDM_REG_SUBKEY, key, RRF_RT_ANY, NULL, *value, &cbDataSize)))) {
        if (*value) {
            free(*value);
            *value = NULL;
        }
        if (HRESULT_FROM_WIN32(ERROR_MORE_DATA) == hr) {
            hr = S_OK;
            if (!(*value = (char *) malloc(cbDataSize))) {
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

int count_char(const char *a, char w) {
    int count = 0;
    const char *b = a;
    if (b)
        while (*b) if (*b++ == w) ++count;
    return count;
}

char * string_replace(const char *original, const char *pattern, const char *replace) {
    size_t pcnt = 0;
    const char * optr;
    const char * ploc;
    if (original != NULL && pattern != NULL && replace != NULL) {
        size_t rlen = strlen(replace);
        size_t plen = strlen(pattern);
        size_t olen = strlen(original);
        for (optr = original; ploc = strstr(optr, pattern); optr = ploc + plen) pcnt++;
        if (pcnt > 0) {
            size_t retlen = olen + pcnt * (rlen - plen);
            char *returned = (char *) malloc(retlen + 1);
            if (returned != NULL) {
                char * retptr = returned;
                for (optr = original; ploc = strstr(optr, pattern); optr = ploc + plen) {
                    size_t slen = ploc - optr;
                    strncpy(retptr, optr, slen);
                    retptr += slen;
                    strncpy(retptr, replace, rlen);
                    retptr += rlen;
                }
                strcpy(retptr, optr);
            }
            return returned;
        }
    }
    return NULL;
}

void free_list(char **list, int listsize) {
    int i;
    if (list != NULL) {
        for (i = 0; i < listsize; i++) {
            if (list[i] != NULL) free(list[i]);
        }
        free(list);
    }
}

static int count_files(const char * filespec) {
    int count = 0;
    struct _finddata_t data;
    intptr_t h;
    if (filespec != NULL) {
        if ((h = _findfirst(filespec, &data)) > -1) {
            do {
                if (!(data.attrib & _A_SUBDIR)) count++;
            } while (_findnext(h, &data) == 0);
            _findclose(h);
        }
    }
    return count;
}

static int compare_files(const void * a, const void * b) {
    return strcoll((char *) b, (char *) a);
}

char ** traverse_directory(const char * dir, int *count) {
    struct _finddata_t data;
    int i = 0;
    intptr_t h;
    char ** list = NULL;
    char * filespec = NULL;
    if (dir != NULL) {
        asprintf(&filespec, "%s/*.json", dir);
        if (filespec != NULL) {
            if ((*count = count_files(filespec)) > 0) {
                list = (char **) malloc((*count) * sizeof (char *));
                if (list != NULL && (h = _findfirst(filespec, &data)) > -1) {
                    do {
                        if (!(data.attrib & _A_SUBDIR)) {
                            list[i] = NULL;
                            asprintf(&(list[i]), "%s/%s", dir, data.name);
                            i++;
                        }
                    } while (_findnext(h, &data) == 0);
                    _findclose(h);
                    if (i > 0) qsort(list, i, sizeof (list[0]), compare_files);
                }
            }
            free(filespec);
        }
    }
    return list;
}

BOOL create_directory(const char *path) {
    char *p = NULL;
    BOOL b = FALSE;
    if (!(b = CreateDirectoryA(path, NULL))
            && !(b = NULL == (p = strrchr(path, '/')))) {
        size_t i;
        (p = strncpy((char *) malloc(i + 2),
                path, i = p - path))[i] = '\0';
        b = create_directory(p);
        free(p);
        b = b ? (CreateDirectoryA(path, NULL) || GetLastError() == ERROR_ALREADY_EXISTS) : FALSE;
    }
    return b;
}

static BOOL encrypt_key(HCRYPTPROV hCryptProv, BYTE * cdata, DWORD cdatasize,
        const char * certf, const char * certp, char ** encoded) {
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

    if ((hfile = CreateFileA(certf, FILE_READ_DATA, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0)) != INVALID_HANDLE_VALUE) {
        if ((hsection = CreateFileMapping(hfile, 0, PAGE_READONLY, 0, 0, 0))) {
            if ((pfx = MapViewOfFile(hsection, FILE_MAP_READ, 0, 0, 0))) {
                blob.cbData = GetFileSize(hfile, 0);
                blob.pbData = (BYTE*) pfx;
                if (PFXIsPFXBlob(&blob)) {
                    wchar_t *certp_w = utf8_decode(certp, NULL);
                    if ((pfxStore = PFXImportCertStore(&blob, certp_w, CRYPT_MACHINE_KEYSET | CRYPT_EXPORTABLE))) {
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
                                                                if ((*encoded = base64_encode(encpww, sizeSource, NULL)) != NULL) {
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
                        } else {
                            LOG(LOG_ERROR, "encrypt_key(): couldn't enumerate keys/certificates in \"%s\"", certf);
                        }
                        CertCloseStore(pfxStore, CERT_CLOSE_STORE_FORCE_FLAG);
                    } else {
                        LOG(LOG_ERROR, "encrypt_key(): couldn't import key file \"%s\"", certf);
                    }
                    if (certp_w != NULL) {
                        free(certp_w);
                    }
                } else {
                    LOG(LOG_ERROR, "encrypt_key(): key file \"%s\" is not of PKCS12 type", certf);
                }
                UnmapViewOfFile(pfx);
            }
            CloseHandle(hsection);
        }
        CloseHandle(hfile);
    } else {
        LOG(LOG_ERROR, "encrypt_key(): key file \"%s\" is not accessible", certf);
    }
    return ret;
}

BOOL encrypt(const char *password, size_t pass_len, const char * certf, const char * certp,
        char ** encrypted, char ** key, ENCR_KEY_ALG alg) {
    BOOL ret = FALSE;
    HCRYPTPROV hProv;
    HCRYPTKEY hKey = 0;
    BYTE *pbKeyBlob = NULL, *pbKeyBlobTemp = NULL, *buffTemp = NULL;
    DWORD dwBlobLen, dwBlobLenTemp, sizeDest, sizeSource = (DWORD) pass_len;
    DWORD dwMode = CRYPT_MODE_ECB;
    DWORD dwPadding = PKCS5_PADDING;
    ALG_ID algid = CALG_AES_128;

    if (password == NULL || certf == NULL || certp == NULL) {
        LOG(LOG_ERROR, "encrypt(): invalid parameters");
        return FALSE;
    } else {
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
                                        CopyMemory(buffTemp, password, sizeSource);
                                        if (CryptEncrypt(hKey, 0, TRUE, 0, buffTemp, &sizeSource, sizeDest)) {
                                            if ((*encrypted = base64_encode(buffTemp, sizeSource, NULL)) != NULL) {
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

    return ret;
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
                            *b64key = base64_encode(blob + 12, (size_t) blob_size - 12, size);
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
            && (key_blob = base64_decode(b64key, strlen(b64key), NULL)) != NULL) {
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
                        *b64encr = base64_encode(out, buf_size, NULL);
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
            && (key_blob = base64_decode(b64key, strlen(b64key), NULL)) != NULL) {
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
                    base64_decode(b64data, strlen(b64data), &data_size) : NULL;
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

void log_info(void *o, const char *format, ...) {
    LOG_MESSAGE *m;
    va_list args;
    va_start(args, format);
    m = (LOG_MESSAGE *) malloc(sizeof (LOG_MESSAGE));
    if (m != NULL) {
        m->level = LOG_INFO;
        m->quit_flag = 0;
        m->msg = NULL;
        m->tid = GetCurrentThreadId();
        m->pid = _getpid();
        m->ts = timestamp_log();
        vasprintf(&(m->msg), format, args);
        queue_enqueue(log_handle, m);
    }
    va_end(args);
}

void log_warning(void *o, const char *format, ...) {
    LOG_MESSAGE *m;
    va_list args;
    va_start(args, format);
    m = (LOG_MESSAGE *) malloc(sizeof (LOG_MESSAGE));
    if (m != NULL) {
        m->level = LOG_WARNING;
        m->quit_flag = 0;
        m->msg = NULL;
        m->tid = GetCurrentThreadId();
        m->pid = _getpid();
        m->ts = timestamp_log();
        vasprintf(&(m->msg), format, args);
        queue_enqueue(log_handle, m);
    }
    va_end(args);
}

void log_error(void *o, const char *format, ...) {
    LOG_MESSAGE *m;
    va_list args;
    va_start(args, format);
    m = (LOG_MESSAGE *) malloc(sizeof (LOG_MESSAGE));
    if (m != NULL) {
        m->level = LOG_ERROR;
        m->quit_flag = 0;
        m->msg = NULL;
        m->tid = GetCurrentThreadId();
        m->pid = _getpid();
        m->ts = timestamp_log();
        vasprintf(&(m->msg), format, args);
        queue_enqueue(log_handle, m);
    }
    va_end(args);
}

void log_debug(void *o, const char *format, ...) {
    LOG_MESSAGE *m;
    va_list args;
    va_start(args, format);
    m = (LOG_MESSAGE *) malloc(sizeof (LOG_MESSAGE));
    if (m != NULL) {
        m->level = LOG_DEBUG;
        m->quit_flag = 0;
        m->msg = NULL;
        m->tid = GetCurrentThreadId();
        m->pid = _getpid();
        m->ts = timestamp_log();
        vasprintf(&(m->msg), format, args);
        queue_enqueue(log_handle, m);
    }
    va_end(args);
}

uint64_t max_log_size() {
#define MAX_FSIZE 5120000 /* 5Mb */
    uint64_t msz = MAX_FSIZE;
    char *lsz = NULL;
    if (!read_registry_key("logSize", &lsz) || lsz[0] == '\0') {
        if (lsz) free(lsz);
        msz = MAX_FSIZE;
    } else {
        msz = (uint64_t) _strtoui64(lsz, NULL, 10);
        if (errno == ERANGE) {
            LOG(LOG_ERROR, "max_log_size(): invalid logSize registry key value. Defaulting to %d bytes", MAX_FSIZE);
            msz = MAX_FSIZE;
        }
        free(lsz);
    }
    return msz;
}
