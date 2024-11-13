#include "main.h"

int wmain(int argc, wchar_t *argv[]) {
  NTSTATUS status = STATUS_SUCCESS;
  MODULE_MEMORY_TYPE Type;
  PBYTE data;
  DWORD cbData, pid = 0, previousPriv;
  PCWCHAR szData, szPubSearch, szSearch, szPrivSave, szEntropy;
  PWCHAR p, fPub = NULL;
  HANDLE hProcess = NULL;
  DECRYPT_DATA dData = {0};
  RSA_MEMORY kData = {0};

  if (CryptAcquireContext(&dData.hProv, NULL, NULL, PROV_RSA_AES,
                          CRYPT_VERIFYCONTEXT))  // RSA / AES context
  {
    mStringArgsByName(argc, argv, L"pubsearch", &szPubSearch, L"c:");
    mStringArgsByName(argc, argv, L"search", &szSearch, L"c:");

    // Handle args e.g. private/public key on input
    if (mStringArgsByName(argc, argv, L"priv", &szData, NULL)) {
      mEcho(
          L"Private key file on command-line: %s, will use it instead "
          L"searching\n",
          szData);
      if (mFileReadData(szData, &data, &cbData)) {
        if (!CryptImportKey(dData.hProv, data, cbData, 0, 0, &dData.hKey))
          PRINT_ERROR_AUTO(L"CryptImportKey");
        LocalFree(data);
      }
    } else if (mFileReadData(RANSOM_PRIKEY_FILE, &data, &cbData)) {
      mEcho(L"Private key "
            L"(" RANSOM_PRIKEY_FILE L") is in current directory, let\'s use "
                                    L"it\n");
      if (!CryptImportKey(dData.hProv, data, cbData, 0, 0, &dData.hKey))
        PRINT_ERROR_AUTO(L"CryptImportKey");
      LocalFree(data);
    } else {
      if (mStringArgsByName(argc, argv, L"pub", &szData, NULL)) {
        mEcho(
            L"Public key file on command-line: %s, will use it instead "
            L"searching\n",
            szData);
        fPub = _wcsdup(szData);
      } else if (mFileExists(RANSOM_PUBKEY_FILE)) {
        mEcho(L"Public key "
              L"(" RANSOM_PUBKEY_FILE L") is in current directory, let\'s use "
                                      L"it\n");
        fPub = _wcsdup(RANSOM_PUBKEY_FILE);
      } else {
        mEcho(L"Public key (" RANSOM_PUBKEY_FILE L") is NOT in current "
                                                 L"directory, let\'s search it "
                                                 L"(in %s)...\n",
              szPubSearch);
        if (!mFindFile(szPubSearch, NULL, TRUE, 0, FALSE, fileCallbackPublicKey,
                       &fPub))
          PRINT_ERROR(L"Public key not found!\n");
      }

      // Start working from public key
      if (fPub) {
        if (rsaPubKeyFileToNewPubKeyEN(fPub, &kData.bigNumExponent,
                                       &kData.bigNumModulus)) {
          echoBigNum(L"Modulus : ", kData.bigNumModulus, L"\n");
          echoBigNum(L"Exponent: ", kData.bigNumExponent, L"\n");

          // Process memory or minidump
          if (mStringArgsByName(argc, argv, L"mdmp", &szData, NULL) ||
              mStringArgsByName(argc, argv, L"dmp", &szData, NULL)) {
            Type = MODULE_MEMORY_TYPE_PROCESS_DMP;
            mEcho(L"Dealing with a minidump file: %s\n", szData);
            hProcess = CreateFile(szData, GENERIC_READ, FILE_SHARE_READ, NULL,
                                  OPEN_EXISTING, 0, NULL);
          } else {
            Type = MODULE_MEMORY_TYPE_PROCESS;
            if (mStringArgsByName(argc, argv, L"process", &szData, NULL)) {
              mEcho(
                  L"Process name on command-line: %s, first process with "
                  L"this name will be inspected\n",
                  szData);
              if (mGetProcessIDForName(szData, &pid))
                mEcho(L"Process found with PID %u\n", pid);
              else
                PRINT_ERROR(L"No process with \'%s\' name was found...\n",
                            szData);
            } else if (mStringArgsByName(argc, argv, L"pid", &szData, NULL)) {
              mEcho(
                  L"Process id on command-line: %s, process with this PID "
                  L"will be inspected\n",
                  szData);
              pid = wcstoul(szData, NULL, 0);
            } else {
              mEcho(L"No process specified, searching for common process...\n");
              if (!(pid = findProcess())) PRINT_ERROR(L"No process found\n");
            }

            if (pid) {
              RtlAdjustPrivilege(20, TRUE, FALSE, &previousPriv);
              hProcess = OpenProcess(
                  PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
              regDeletePendingFileRenameOps();
            } else
              PRINT_ERROR(L"No valid PID\n");
          }

          // Entropy
          if (mStringArgsByName(argc, argv, L"entropy", &szEntropy, NULL))
            kData.minEntropy = wcstod(szEntropy, NULL);
          else
            kData.minEntropy = 0.5;
          mEcho(L"Minimal entropy: %.2f\n", kData.minEntropy);

          // Try to get private key from memory
          if (hProcess && (hProcess != INVALID_HANDLE_VALUE)) {
            if (mMemoryOpen(Type, hProcess, &kData.hProcessMemory)) {
              if (checkValidArchitecture(kData.hProcessMemory)) {
                if (NT_SUCCESS(mProcessGetMemInfo(kData.hProcessMemory,
                                                  memoryAnalysis, &kData))) {
                  if (kData.rsa) { // If we got the key
                    if (rsaToPrivateKeyBlob(kData.rsa, &data, &cbData)) {
                      if (!mStringArgsByName(argc, argv, L"noprivsave", NULL,
                                             NULL)) {
                        if (!mStringArgsByName(argc, argv, L"privsave",
                                               &szPrivSave, NULL)) {
                          if (p = wcsrchr(fPub, L'.')) {
                            *(p + 1) = L'd';
                            szPrivSave = fPub;
                          } else
                            szPrivSave = RANSOM_PRIKEY_FILE;
                        }
                        mEcho(
                            L"Let\'s save privatekey blob in %s file (for "
                            L"wannadecrypt or original WannaDecrypt0r 2.0...)\n",
                            szPrivSave);
                        mFileWriteData(szPrivSave, data, cbData);
                      } else
                        mEcho(
                            L"Only dealing with saving key on disk when "
                            L"/noprivsave argument is used\n");

                      if (!CryptImportKey(dData.hProv, data, cbData, 0, 0,
                                          &dData.hKey))
                        PRINT_ERROR_AUTO(L"CryptImportKey");
                      LocalFree(data);
                    } else
                      PRINT_ERROR(
                          L"OpenSSL doesn\'t want to convert to MS "
                          L"PRIVATEKEYBLOB format\n");
                    RSA_free(kData.rsa);
                  } else
                    PRINT_ERROR(
                        L"Unfortunately, no correct privatekey in memory :(\n");
                } else
                  PRINT_ERROR(L"Minidump without MemoryInfoListStream?\n");
              } else
                PRINT_ERROR(L"Memory is not PROCESSOR_ARCHITECTURE_INTEL\n");
            }
            CloseHandle(hProcess);
          } else
            PRINT_ERROR_AUTO(L"Invalid handle (CreateFile/OpenProcess)");
          BN_free(kData.bigNumExponent);
          BN_free(kData.bigNumModulus);
        }
        free(fPub);
      }
    }

    // Start working with private key
    if (dData.hKey) {
      if (!mStringArgsByName(argc, argv, L"nodecrypt", NULL, NULL)) {
        if ((Type == MODULE_MEMORY_TYPE_PROCESS) ||
            mStringArgsByName(argc, argv, L"forcedecrypt", NULL, NULL)) {
          rsaInitDefaultKey(&dData.hFreeProv, &dData.hFreeKey);
          mEcho(L"Now searching " RANSOM_FILE_EXT L" files in %s...\n",
                szSearch);
          mFindFile(szSearch, NULL, TRUE, 0, FALSE, fileCallbackWannaCry,
                    &dData);
          rsaFreeDefaultKey(dData.hFreeProv, dData.hFreeKey);
        } else
          mEcho(
              L"Only dealing with keys in MINIDUMP mode, use /forcedecrypt "
              L"to search for files\n");
      } else
        mEcho(L"Only dealing with keys when /nodecrypt argument is used\n");
      CryptDestroyKey(dData.hKey);
    }
    CryptReleaseContext(dData.hProv, 0);
  } else
    PRINT_ERROR_AUTO(L"CryptAcquireContext");
  return status;
}

const PCWCHAR proc[] = {
    L"wnry.exe",
    L"wcry.exe",
    L"data_1.exe",
    L"tasksche.exe",
    L"ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa.exe",
    L"5ff465afaabcbf0150d1a3ab2c2e74f3a4426467.exe",
    L"84c82835a5d21bbcf75a61706d8ab549.exe",
};
DWORD findProcess() {
  DWORD i, p = 0;
  for (i = 0; i < ARRAYSIZE(proc); i++) {
    if (mGetProcessIDForName(proc[i], &p)) {
      mEcho(L"Process \'%s\' found with PID: %u\n", proc[i], p);
      break;
    }
  }
  return p;
}

BOOL CALLBACK memoryAnalysis(PMEMORY_BASIC_INFORMATION pMemoryBasicInformation,
                             PVOID pvArg) {
  BOOL found = FALSE;
  MODULE_MEMORY_ADDRESS aBuffer = {NULL, &MODULE_MEMORY_GLOBAL_OWN_HANDLE},
                        aProcess = {pMemoryBasicInformation->BaseAddress,
                                    ((PRSA_MEMORY)pvArg)->hProcessMemory};
  PBYTE i, end;
  BIGNUM *bignum_prime1, *bignum_prime2, *bignum_r;
  BN_CTX *ctx;

  if ((pMemoryBasicInformation->Type == MEM_PRIVATE) &&
      (pMemoryBasicInformation->State != MEM_RESERVE) &&
      (pMemoryBasicInformation->Protect == PAGE_READWRITE)) {
    mEcho(L".");
    if (aBuffer.address =
            LocalAlloc(LPTR, pMemoryBasicInformation->RegionSize)) {
      if (mMemoryCopy(&aBuffer, &aProcess,
                      pMemoryBasicInformation->RegionSize)) {
        mMemoryReverseBytes(aBuffer.address,
                            pMemoryBasicInformation->RegionSize);
        end = (PBYTE)aBuffer.address + pMemoryBasicInformation->RegionSize -
              RSA_2048_PRIM;

        ctx = BN_CTX_new();
        BN_CTX_start(ctx);
        bignum_prime1 = BN_CTX_get(ctx);
        bignum_prime2 = BN_CTX_get(ctx);
        bignum_r = BN_CTX_get(ctx);

        for (i = (PBYTE)aBuffer.address; (i < end) && !found; i += 4) {
          if (rsaNormalizedEntropy(i, RSA_2048_PRIM) >
              ((PRSA_MEMORY)pvArg)->minEntropy) {
            if (BN_bin2bn(i, RSA_2048_PRIM, bignum_prime1) &&
                BN_div(bignum_prime2, bignum_r,
                       ((PRSA_MEMORY)pvArg)->bigNumModulus, bignum_prime1,
                       ctx) &&
                BN_is_zero(bignum_r)) {
              echoBigNum(L"\nPrime1: ", bignum_prime1, L"\n");
              echoBigNum(L"Prime2: ", bignum_prime2, L"\n");
              ((PRSA_MEMORY)pvArg)->rsa = RSA_new();
              if (!(found =
                        rsaQuickImport(((PRSA_MEMORY)pvArg)->rsa,
                                       ((PRSA_MEMORY)pvArg)->bigNumExponent,
                                       bignum_prime1, bignum_prime2, NULL))) {
                PRINT_ERROR(
                    L"Unable to import raw key as a RSA key (?) -- continue\n");
                RSA_free(((PRSA_MEMORY)pvArg)->rsa);
                ((PRSA_MEMORY)pvArg)->rsa = NULL;
              }
            }
          }
        }
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
      } else
        PRINT_ERROR(L"memory copy @ p (%u)\n",
                    pMemoryBasicInformation->BaseAddress,
                    pMemoryBasicInformation->RegionSize);
      LocalFree(aBuffer.address);
    }
  }
  return !found;
}

BOOL CALLBACK fileCallbackPublicKey(DWORD level, PCWCHAR fullPath, PCWCHAR path,
                                    PVOID pvArg) {
  BOOL status = FALSE;
  if (status = (_wcsicmp(path, RANSOM_PUBKEY_FILE) == 0)) {
    mEcho(L"Public key found: %s\n", fullPath);
    *(PWSTR *)pvArg = _wcsdup(fullPath);
  }
  return status;
}

BOOL CALLBACK fileCallbackWannaCry(DWORD level, PCWCHAR fullPath, PCWCHAR path,
                                   PVOID pvArg) {
  BOOL status = FALSE;
  PDECRYPT_DATA pData = (PDECRYPT_DATA)pvArg;
  PWSTR ext = PathFindExtension(path);
  if (ext && (_wcsicmp(ext, RANSOM_FILE_EXT) == 0))
    rsaDecryptFileWithKey(pData->hProv, pData->hKey, pData->hFreeKey,
                          (LPWSTR)fullPath);
  return status;
}

void echoBigNum(PCWCHAR pre, BIGNUM *bn, PCWCHAR post) {
  PCHAR outs;
  if (pre) mEcho(pre);
  outs = BN_bn2hex(bn);
  mEcho(L"%S", outs);
  OPENSSL_free(outs);
  if (post) mEcho(post);
}

BOOL checkValidArchitecture(PMODULE_MEMORY_HANDLE hMemory) {
  BOOL status = FALSE;
  PMINIDUMP_SYSTEM_INFO pInfos;
  if (hMemory->type == MODULE_MEMORY_TYPE_PROCESS_DMP) {
    if (pInfos = (PMINIDUMP_SYSTEM_INFO)mMiniDumpStream(
            hMemory->pHandleProcessDmp->hMinidump, SystemInfoStream))
      status = (pInfos->ProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL);
    else
      PRINT_ERROR(L"Minidump without SystemInfoStream (?)\n");
  } else
    status = FALSE;
  return TRUE;
}

BOOL regDeletePendingFileRenameOps() {
  BOOL status = FALSE;
  HKEY hKey;
  DWORD dwRet =
      RegOpenKeyEx(HKEY_LOCAL_MACHINE,
                   L"System\\CurrentControlSet\\Control\\Session Manager",
                   FALSE, KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey);
  if (dwRet == ERROR_SUCCESS) {
    dwRet = RegQueryValueEx(hKey, L"PendingFileRenameOperations", NULL, NULL,
                            NULL, NULL);
    if (dwRet == ERROR_SUCCESS) {
      mEcho(
          L"\'PendingFileRenameOperations\' registry value is present and "
          L"will now be deleted\n");
      dwRet = RegDeleteValue(hKey, L"PendingFileRenameOperations");
      if (!(status = (dwRet == ERROR_SUCCESS)))
        PRINT_ERROR(L"RegDeleteValue: %u\n", dwRet);
    } else if (dwRet != ERROR_FILE_NOT_FOUND)
      PRINT_ERROR(L"RegQueryValueEx: %u\n", dwRet);
    RegCloseKey(hKey);
  } else
    PRINT_ERROR(L"RegOpenKeyEx: %u\n", dwRet);
  return status;
}
