#pragma once

#include <math.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "./globals.h"
#include "../modules/module_file.h"

#define RSA_2048_ENC 256  // 2048 / 8
#define RSA_2048_PRIM (RSA_2048_ENC / 2)
#define RANSOM_MAGIC ((ULONGLONG)0x21595243414e4157)  // WannaCry!
#define RSA_ENC_SIZE (RSA_2048_ENC * 5)
#define RSA_DEC_SIZE 1172
#define RSA_BAD_PAD 1225

typedef struct _RANSOM_FORMAT {
  ULONGLONG magic;    // RANSOM_MAGIC
  ULONG enc_keysize;  // RSA_2048_ENC
  BYTE key[RSA_2048_ENC];
  ULONG unkOperation;  // 4
  ULONGLONG qwDataSize;
  BYTE data[ANYSIZE_ARRAY];
} RANSOM_FORMAT, *PRANSOM_FORMAT;

typedef struct _GENERICKEY_BLOB {
  BLOBHEADER Header;
  DWORD dwKeyLen;
} GENERICKEY_BLOB, *PGENERICKEY_BLOB;

typedef struct _ENC_PRIV_KEY {
  DWORD totalBytes;
  BYTE data[ANYSIZE_ARRAY][RSA_2048_ENC];
} ENC_PRIV_KEY, *PENC_PRIV_KEY;

typedef struct _DEC_PRIV_KEY {
  DWORD totalBytes;
  BYTE data[ANYSIZE_ARRAY];
} DEC_PRIV_KEY, *PDEC_PRIV_KEY;

BOOL rsaQuickImport(RSA *rsa, BIGNUM *e_value, BIGNUM *p_value, BIGNUM *q_value,
                    OPTIONAL BIGNUM *n_value);
BOOL rsaToPrivateKeyBlob(RSA *rsa, PBYTE *blob, DWORD *cbBlob);
BOOL rsaPubKeyBlobToRSA(PBYTE blob, DWORD cbBlob, RSA **rsa);
BOOL rsaPubKeyFileToNewPubKeyEN(PCWSTR filename, BIGNUM **e, BIGNUM **n);
BOOL rsaSimpleModuleCryptoHKEY(HCRYPTPROV hProv, ALG_ID calgid, LPCVOID key,
                               DWORD keyLen, DWORD flags, HCRYPTKEY *hKey);
BOOL rsaInitDefaultKey(HCRYPTPROV *hProv, HCRYPTKEY *hKey);
void rsaFreeDefaultKey(HCRYPTPROV hProv, HCRYPTKEY hKey);
void rsaDecryptFileWithKey(HCRYPTPROV hProv, HCRYPTKEY hUserRsaKey,
                           HCRYPTKEY hFreeRsaKey, LPWSTR filename);
DOUBLE rsaNormalizedEntropy(LPCBYTE data, DWORD len);
unsigned char default_user_pky[1172];
