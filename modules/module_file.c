#include "module_file.h"

BOOL isBase64InterceptOutput = FALSE, isBase64InterceptInput = FALSE;

BOOL mFileExists(PCWCHAR fileName) {
  BOOL reussite = FALSE;
  HANDLE hFile = NULL;

  reussite = ((hFile = CreateFile(fileName, 0, FILE_SHARE_READ, NULL,
                                  OPEN_EXISTING, 0, NULL)) &&
              hFile != INVALID_HANDLE_VALUE);
  if (reussite) CloseHandle(hFile);
  return reussite;
}

BOOL mFileWriteData(PCWCHAR fileName, LPCVOID data, DWORD lenght) {
  BOOL reussite = FALSE;
  DWORD dwBytesWritten = 0, i;
  HANDLE hFile = NULL;
  LPWSTR base64;

  if (isBase64InterceptOutput) {
    if (CryptBinaryToString((const BYTE *)data, lenght, CRYPT_STRING_BASE64,
                            NULL, &dwBytesWritten)) {
      if (base64 = (LPWSTR)LocalAlloc(LPTR, dwBytesWritten * sizeof(wchar_t))) {
        if (reussite = CryptBinaryToString((const BYTE *)data, lenght,
                                           CRYPT_STRING_BASE64, base64,
                                           &dwBytesWritten)) {
          mEcho(
              L"\n====================\nBase64 of file : "
              L"%s\n====================\n",
              fileName);
          for (i = 0; i < dwBytesWritten; i++) mEcho(L"%c", base64[i]);
          mEcho(L"====================\n");
        }
        LocalFree(base64);
      }
    }
  } else if ((hFile = CreateFile(fileName, GENERIC_WRITE, 0, NULL,
                                 CREATE_ALWAYS, 0, NULL)) &&
             hFile != INVALID_HANDLE_VALUE) {
    if (WriteFile(hFile, data, lenght, &dwBytesWritten, NULL) &&
        (lenght == dwBytesWritten))
      reussite = FlushFileBuffers(hFile);
    CloseHandle(hFile);
  }
  return reussite;
}

BOOL mFileReadData(PCWCHAR fileName, PBYTE *data,
                   PDWORD lenght) {  // for ""little"" files !
  BOOL reussite = FALSE;
  DWORD dwBytesReaded;
  LARGE_INTEGER filesize;
  HANDLE hFile = NULL;

  if (isBase64InterceptInput) {
    if (!(reussite =
              module_string_quick_base64_to_Binary(fileName, data, lenght)))
      PRINT_ERROR_AUTO(L"module_string_quick_base64_to_Binary");
  } else if ((hFile = CreateFile(fileName, GENERIC_READ, FILE_SHARE_READ, NULL,
                                 OPEN_EXISTING, 0, NULL)) &&
             hFile != INVALID_HANDLE_VALUE) {
    if (GetFileSizeEx(hFile, &filesize) && !filesize.HighPart) {
      *lenght = filesize.LowPart;
      if (*data = (PBYTE)LocalAlloc(LPTR, *lenght)) {
        if (!(reussite =
                  ReadFile(hFile, *data, *lenght, &dwBytesReaded, NULL) &&
                  (*lenght == dwBytesReaded)))
          LocalFree(*data);
      }
    }
    CloseHandle(hFile);
  }
  return reussite;
}

BOOL mFindFile(PCWCHAR directory, PCWCHAR filter, BOOL isRecursive /*TODO*/,
               DWORD level, BOOL isPrintInfos,
               PMODULE_FILE_FIND_CALLBACK callback, PVOID pvArg) {
  BOOL status = FALSE;
  DWORD dwAttrib;
  HANDLE hFind;
  WIN32_FIND_DATA fData;
  PWCHAR fullPath;

  dwAttrib = GetFileAttributes(directory);
  if ((dwAttrib != INVALID_FILE_ATTRIBUTES) &&
      (dwAttrib & FILE_ATTRIBUTE_DIRECTORY)) {
    if (isPrintInfos && !level) {
      mEcho(
          L"%*s"
          L"Directory \'%s\'",
          level << 1, L"", directory);
      if (filter) mEcho(L" (%s)", filter);
      mEcho(L"\n");
    }
    if (fullPath = (wchar_t *)LocalAlloc(LPTR, MAX_PATH * sizeof(wchar_t))) {
      if (wcscpy_s(fullPath, MAX_PATH, directory) == 0) {
        if (wcscat_s(fullPath, MAX_PATH, L"\\") == 0) {
          if (wcscat_s(fullPath, MAX_PATH, filter ? filter : L"*") == 0) {
            hFind = FindFirstFile(fullPath, &fData);
            if (hFind != INVALID_HANDLE_VALUE) {
              do {
                if (_wcsicmp(fData.cFileName, L".") &&
                    _wcsicmp(fData.cFileName, L"..")) {
                  if (wcscpy_s(fullPath, MAX_PATH, directory) == 0) {
                    if (wcscat_s(fullPath, MAX_PATH, L"\\") == 0) {
                      dwAttrib = (DWORD)wcslen(fullPath);
                      if (wcscat_s(fullPath, MAX_PATH, fData.cFileName) == 0) {
                        if (isPrintInfos)
                          mEcho(
                              L"%*s"
                              L"%3u %c|'%s\'\n",
                              level << 1, L"", level,
                              (fData.dwFileAttributes &
                               FILE_ATTRIBUTE_DIRECTORY)
                                  ? L'D'
                                  : L'F',
                              fData.cFileName);

                        if (!(fData.dwFileAttributes &
                              FILE_ATTRIBUTE_DIRECTORY)) {
                          if (callback)
                            status = callback(level, fullPath,
                                              fullPath + dwAttrib, pvArg);
                        } else if (isRecursive && fData.cFileName)
                          status = mFindFile(fullPath, filter, TRUE, level + 1,
                                             isPrintInfos, callback, pvArg);
                      }
                    }
                  }
                }
              } while (!status && FindNextFile(hFind, &fData));
              FindClose(hFind);
            }
          }
        }
      }
    }
    LocalFree(fullPath);
  }
  return status;
}
