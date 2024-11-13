#pragma once

#include "./globals.h"
#include "../modules/module_file.h"
#include "../modules/module_memory.h"
#include "../modules/module_process.h"
#include "../modules/module_string.h"
#include "_rsa.h"

typedef struct _RSA_MEMORY_DATA {
  PMODULE_MEMORY_HANDLE hProcessMemory;
  DOUBLE minEntropy;
  BIGNUM *bigNumModulus;
  BIGNUM *bigNumExponent;
  RSA *rsa;
} RSA_MEMORY, *PRSA_MEMORY;

typedef struct _DECRYPT_DATA {
  HCRYPTPROV hProv;
  HCRYPTKEY hKey;
  HCRYPTPROV hFreeProv;
  HCRYPTKEY hFreeKey;
} DECRYPT_DATA, *PDECRYPT_DATA;

int wmain(int argc, wchar_t *argv[]);
DWORD findProcess();
BOOL CALLBACK memoryAnalysis(PMEMORY_BASIC_INFORMATION pMemoryBasicInformation,
                             PVOID pvArg);
BOOL CALLBACK fileCallbackPublicKey(DWORD level, PCWCHAR fullPath, PCWCHAR path,
                                    PVOID pvArg);
BOOL CALLBACK fileCallbackWannaCry(DWORD level, PCWCHAR fullPath, PCWCHAR path,
                                   PVOID pvArg);
void echoBigNum(PCWCHAR pre, BIGNUM *bn, PCWCHAR post);
BOOL checkValidArchitecture(PMODULE_MEMORY_HANDLE hMemory);
BOOL regDeletePendingFileRenameOps();
