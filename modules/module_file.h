#pragma once

#include <shlwapi.h>

#include "../src/globals.h"
#include "module_string.h"

BOOL isBase64InterceptOutput, isBase64InterceptInput;

typedef BOOL(CALLBACK* PMODULE_FILE_FIND_CALLBACK)(DWORD level,
                                                   PCWCHAR fullPath,
                                                   PCWCHAR path, PVOID pvArg);

BOOL mFileExists(PCWCHAR fileName);
BOOL mFileWriteData(PCWCHAR fileName, LPCVOID data, DWORD lenght);
BOOL mFileReadData(PCWCHAR fileName, PBYTE* data,
                   PDWORD lenght);  // for 'little' files !
BOOL mFindFile(PCWCHAR directory, PCWCHAR filter, BOOL isRecursive /*TODO*/,
               DWORD level, BOOL isPrintInfos,
               PMODULE_FILE_FIND_CALLBACK callback, PVOID pvArg);
