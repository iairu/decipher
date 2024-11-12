#pragma once

#include <dbghelp.h>

#include "../src/globals.h"

typedef struct _MODULE_MINIDUMP_HANDLE {
  HANDLE hFileMapping;
  LPVOID pMapViewOfFile;
} MODULE_MINIDUMP_HANDLE, *PMODULE_MINIDUMP_HANDLE;

BOOL mMiniDumpOpen(IN HANDLE hFile, OUT PMODULE_MINIDUMP_HANDLE *hMinidump);
BOOL mMiniDumpClose(IN PMODULE_MINIDUMP_HANDLE hMinidump);
BOOL mMiniDumpCopy(IN PMODULE_MINIDUMP_HANDLE hMinidump, OUT VOID *Destination,
                   IN VOID *Source, IN SIZE_T Length);

LPVOID mMiniDumpRVAtoPTR(IN PMODULE_MINIDUMP_HANDLE hMinidump, RVA64 rva);
LPVOID mMiniDumpStream(IN PMODULE_MINIDUMP_HANDLE hMinidump,
                       MINIDUMP_STREAM_TYPE type);
