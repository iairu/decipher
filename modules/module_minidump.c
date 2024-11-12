#include "module_minidump.h"

BOOL mMiniDumpOpen(IN HANDLE hFile, OUT PMODULE_MINIDUMP_HANDLE *hMinidump) {
  BOOL status = FALSE;

  *hMinidump =
      (PMODULE_MINIDUMP_HANDLE)LocalAlloc(LPTR, sizeof(MODULE_MINIDUMP_HANDLE));
  if (*hMinidump) {
    (*hMinidump)->hFileMapping =
        CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if ((*hMinidump)->hFileMapping) {
      if ((*hMinidump)->pMapViewOfFile =
              MapViewOfFile((*hMinidump)->hFileMapping, FILE_MAP_READ, 0, 0, 0))
        status = (((PMINIDUMP_HEADER)(*hMinidump)->pMapViewOfFile)->Signature ==
                  MINIDUMP_SIGNATURE) &&
                 ((WORD)(((PMINIDUMP_HEADER)(*hMinidump)->pMapViewOfFile)
                             ->Version) == MINIDUMP_VERSION);
    }
    if (!status) mMiniDumpClose(*hMinidump);
  }
  return status;
}

BOOL mMiniDumpClose(IN PMODULE_MINIDUMP_HANDLE hMinidump) {
  if (hMinidump->pMapViewOfFile) UnmapViewOfFile(hMinidump->pMapViewOfFile);
  if (hMinidump->hFileMapping) CloseHandle(hMinidump->hFileMapping);
  return TRUE;
}

LPVOID mMiniDumpRVAtoPTR(IN PMODULE_MINIDUMP_HANDLE hMinidump, RVA64 rva) {
  return (PBYTE)(hMinidump->pMapViewOfFile) + rva;
}

LPVOID mMiniDumpStream(IN PMODULE_MINIDUMP_HANDLE hMinidump,
                       MINIDUMP_STREAM_TYPE type) {
  ULONG32 i;
  PMINIDUMP_DIRECTORY pStreamDirectory = (PMINIDUMP_DIRECTORY)mMiniDumpRVAtoPTR(
      hMinidump,
      ((PMINIDUMP_HEADER)(hMinidump->pMapViewOfFile))->StreamDirectoryRva);

  for (i = 0;
       i < ((PMINIDUMP_HEADER)(hMinidump->pMapViewOfFile))->NumberOfStreams;
       i++) {
    if (pStreamDirectory[i].StreamType == type)
      return mMiniDumpRVAtoPTR(hMinidump, pStreamDirectory[i].Location.Rva);
  }
  return NULL;
}

BOOL mMiniDumpCopy(IN PMODULE_MINIDUMP_HANDLE hMinidump, OUT VOID *Destination,
                   IN VOID *Source, IN SIZE_T Length) {
  BOOL status = FALSE;
  PMINIDUMP_MEMORY64_LIST myDir = NULL;

  PBYTE ptr;
  ULONG64 nMemory64;
  PMINIDUMP_MEMORY_DESCRIPTOR64 memory64;
  ULONG64 offsetToRead, offsetToWrite, lengthToRead, lengthReaded = 0;

  if (myDir = (PMINIDUMP_MEMORY64_LIST)mMiniDumpStream(hMinidump,
                                                       Memory64ListStream)) {
    ptr = (PBYTE)mMiniDumpRVAtoPTR(hMinidump, myDir->BaseRva);
    for (nMemory64 = 0; nMemory64 < myDir->NumberOfMemoryRanges;
         nMemory64++, ptr += memory64->DataSize) {
      memory64 = &(myDir->MemoryRanges[nMemory64]);
      if ((((ULONG64)Source >= memory64->StartOfMemoryRange) &&
           ((ULONG64)Source <
            (memory64->StartOfMemoryRange + memory64->DataSize))) ||
          (((ULONG64)Source + Length >= memory64->StartOfMemoryRange) &&
           ((ULONG64)Source + Length <
            (memory64->StartOfMemoryRange + memory64->DataSize))) ||
          (((ULONG64)Source < memory64->StartOfMemoryRange) &&
           ((ULONG64)Source + Length >
            (memory64->StartOfMemoryRange + memory64->DataSize)))) {
        if ((ULONG64)Source < memory64->StartOfMemoryRange) {
          offsetToRead = 0;
          offsetToWrite = memory64->StartOfMemoryRange - (ULONG64)Source;
        } else {
          offsetToRead = (ULONG64)Source - memory64->StartOfMemoryRange;
          offsetToWrite = 0;
        }
        lengthToRead = Length - offsetToWrite;
        if (offsetToRead + lengthToRead > memory64->DataSize)
          lengthToRead = memory64->DataSize - offsetToRead;

        RtlCopyMemory((PBYTE)Destination + offsetToWrite, ptr + offsetToRead,
                      (SIZE_T)lengthToRead);
        lengthReaded += lengthToRead;
      }
    }
    status = (lengthReaded == Length);
  }
  return status;
}
