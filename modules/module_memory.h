#pragma once

#include "../src/globals.h"
#include "module_minidump.h"

typedef enum _MODULE_MEMORY_TYPE {
  MODULE_MEMORY_TYPE_OWN,
  MODULE_MEMORY_TYPE_PROCESS,
  MODULE_MEMORY_TYPE_PROCESS_DMP,
} MODULE_MEMORY_TYPE;

typedef struct _MODULE_MEMORY_HANDLE_PROCESS {
  HANDLE hProcess;
} MODULE_MEMORY_HANDLE_PROCESS, *PMODULE_MEMORY_HANDLE_PROCESS;

typedef struct _MODULE_MEMORY_HANDLE_PROCESS_DMP {
  PMODULE_MINIDUMP_HANDLE hMinidump;
} MODULE_MEMORY_HANDLE_PROCESS_DMP, *PMODULE_MEMORY_HANDLE_PROCESS_DMP;

typedef struct _MODULE_MEMORY_HANDLE {
  MODULE_MEMORY_TYPE type;
  union {
    PMODULE_MEMORY_HANDLE_PROCESS pHandleProcess;
    PMODULE_MEMORY_HANDLE_PROCESS_DMP pHandleProcessDmp;
  };
} MODULE_MEMORY_HANDLE, *PMODULE_MEMORY_HANDLE;
MODULE_MEMORY_HANDLE MODULE_MEMORY_GLOBAL_OWN_HANDLE;

typedef struct _MODULE_MEMORY_ADDRESS {
  LPVOID address;
  PMODULE_MEMORY_HANDLE hMemory;
} MODULE_MEMORY_ADDRESS, *PMODULE_MEMORY_ADDRESS;

typedef struct _MODULE_MEMORY_RANGE {
  MODULE_MEMORY_ADDRESS module_memoryAdress;
  SIZE_T size;
} MODULE_MEMORY_RANGE, *PMODULE_MEMORY_RANGE;

typedef struct _MODULE_MEMORY_SEARCH {
  MODULE_MEMORY_RANGE module_memoryRange;
  LPVOID result;
} MODULE_MEMORY_SEARCH, *PMODULE_MEMORY_SEARCH;

BOOL mMemoryCopy(OUT PMODULE_MEMORY_ADDRESS Destination,
                 IN PMODULE_MEMORY_ADDRESS Source, IN SIZE_T Length);
BOOL mMemoryOpen(IN MODULE_MEMORY_TYPE Type, IN HANDLE hAny,
                 OUT PMODULE_MEMORY_HANDLE *hMemory);

#define COMPRESSION_FORMAT_NONE (0x0000)     // winnt
#define COMPRESSION_FORMAT_DEFAULT (0x0001)  // winnt
#define COMPRESSION_FORMAT_LZNT1 (0x0002)    // winnt

#define COMPRESSION_ENGINE_STANDARD (0x0000)  // winnt
#define COMPRESSION_ENGINE_MAXIMUM (0x0100)   // winnt
#define COMPRESSION_ENGINE_HIBER (0x0200)     // winnt

NTSYSAPI NTSTATUS NTAPI
RtlGetCompressionWorkSpaceSize(__in USHORT CompressionFormatAndEngine,
                               __out PULONG CompressBufferWorkSpaceSize,
                               __out PULONG CompressFragmentWorkSpaceSize);
NTSYSAPI NTSTATUS NTAPI RtlCompressBuffer(
    __in USHORT CompressionFormatAndEngine,
    __in_bcount(UncompressedBufferSize) PUCHAR UncompressedBuffer,
    __in ULONG UncompressedBufferSize,
    __out_bcount_part(CompressedBufferSize, *FinalCompressedSize)
        PUCHAR CompressedBuffer,
    __in ULONG CompressedBufferSize, __in ULONG UncompressedChunkSize,
    __out PULONG FinalCompressedSize, __in PVOID WorkSpace);
NTSYSAPI NTSTATUS NTAPI RtlDecompressBuffer(
    __in USHORT CompressionFormat,
    __out_bcount_part(UncompressedBufferSize, *FinalUncompressedSize)
        PUCHAR UncompressedBuffer,
    __in ULONG UncompressedBufferSize,
    __in_bcount(CompressedBufferSize) PUCHAR CompressedBuffer,
    __in ULONG CompressedBufferSize, __out PULONG FinalUncompressedSize);

void mMemoryReverseBytes(PVOID start, SIZE_T size);
