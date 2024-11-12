#include "module_memory.h"

MODULE_MEMORY_HANDLE MODULE_MEMORY_GLOBAL_OWN_HANDLE = {MODULE_MEMORY_TYPE_OWN,
                                                        NULL};

BOOL mMemoryOpen(IN MODULE_MEMORY_TYPE Type, IN HANDLE hAny,
                 OUT PMODULE_MEMORY_HANDLE *hMemory) {
  BOOL status = FALSE;

  *hMemory =
      (PMODULE_MEMORY_HANDLE)LocalAlloc(LPTR, sizeof(MODULE_MEMORY_HANDLE));
  if (*hMemory) {
    (*hMemory)->type = Type;
    switch (Type) {
      case MODULE_MEMORY_TYPE_OWN:
        status = TRUE;
        break;
      case MODULE_MEMORY_TYPE_PROCESS:
        if ((*hMemory)->pHandleProcess =
                (PMODULE_MEMORY_HANDLE_PROCESS)LocalAlloc(
                    LPTR, sizeof(MODULE_MEMORY_HANDLE_PROCESS))) {
          (*hMemory)->pHandleProcess->hProcess = hAny;
          status = TRUE;
        }
        break;
      case MODULE_MEMORY_TYPE_PROCESS_DMP:
        if ((*hMemory)->pHandleProcessDmp =
                (PMODULE_MEMORY_HANDLE_PROCESS_DMP)LocalAlloc(
                    LPTR, sizeof(MODULE_MEMORY_HANDLE_PROCESS_DMP)))
          status =
              mMiniDumpOpen(hAny, &(*hMemory)->pHandleProcessDmp->hMinidump);
        break;
      default:
        break;
    }
    if (!status) LocalFree(*hMemory);
  }
  return status;
}

BOOL mMemoryCopy(OUT PMODULE_MEMORY_ADDRESS Destination,
                 IN PMODULE_MEMORY_ADDRESS Source, IN SIZE_T Length) {
  BOOL status = FALSE;
  BOOL bufferMeFirst = FALSE;
  MODULE_MEMORY_ADDRESS aBuffer = {NULL, &MODULE_MEMORY_GLOBAL_OWN_HANDLE};

  switch (Destination->hMemory->type) {
    case MODULE_MEMORY_TYPE_OWN:
      switch (Source->hMemory->type) {
        case MODULE_MEMORY_TYPE_OWN:
          RtlCopyMemory(Destination->address, Source->address, Length);
          status = TRUE;
          break;
        case MODULE_MEMORY_TYPE_PROCESS:
          status = ReadProcessMemory(Source->hMemory->pHandleProcess->hProcess,
                                     Source->address, Destination->address,
                                     Length, NULL);
          break;
        case MODULE_MEMORY_TYPE_PROCESS_DMP:
          status = mMiniDumpCopy(Source->hMemory->pHandleProcessDmp->hMinidump,
                                 Destination->address, Source->address, Length);
          break;
        default:
          break;
      }
      break;
    case MODULE_MEMORY_TYPE_PROCESS:
      switch (Source->hMemory->type) {
        case MODULE_MEMORY_TYPE_OWN:
          status = WriteProcessMemory(
              Destination->hMemory->pHandleProcess->hProcess,
              Destination->address, Source->address, Length, NULL);
          break;
        default:
          bufferMeFirst = TRUE;
          break;
      }
      break;
    default:
      break;
  }

  if (bufferMeFirst) {
    if (aBuffer.address = LocalAlloc(LPTR, Length)) {
      if (mMemoryCopy(&aBuffer, Source, Length))
        status = mMemoryCopy(Destination, &aBuffer, Length);
      LocalFree(aBuffer.address);
    }
  }
  return status;
}

void mMemoryReverseBytes(PVOID start, SIZE_T size) {
  PBYTE lo = (PBYTE)start, hi = lo + size - 1;
  BYTE swap;
  while (lo < hi) {
    swap = *lo;
    *lo++ = *hi;
    *hi-- = swap;
  }
}
