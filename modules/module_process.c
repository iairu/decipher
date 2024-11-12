#include "module_process.h"

NTSTATUS mNTQuerySystemInformation(SYSTEM_INFORMATION_CLASS informationClass,
                                   PVOID buffer, ULONG informationLength) {
  NTSTATUS status = STATUS_INFO_LENGTH_MISMATCH;
  DWORD sizeOfBuffer;

  if (*(PVOID *)buffer) {
    status = NtQuerySystemInformation(informationClass, *(PVOID *)buffer,
                                      informationLength, NULL);
  } else {
    for (sizeOfBuffer = 0x1000;
         (status == STATUS_INFO_LENGTH_MISMATCH) &&
         (*(PVOID *)buffer = LocalAlloc(LPTR, sizeOfBuffer));
         sizeOfBuffer <<= 1) {
      status = NtQuerySystemInformation(informationClass, *(PVOID *)buffer,
                                        sizeOfBuffer, NULL);
      if (!NT_SUCCESS(status)) LocalFree(*(PVOID *)buffer);
    }
  }
  return status;
}

NTSTATUS mGetProcessInformation(PMODULE_PROCESS_ENUM_CALLBACK callBack,
                                PVOID pvArg) {
  NTSTATUS status;
  PSYSTEM_PROCESS_INFORMATION buffer = NULL, myInfos;

  status = mNTQuerySystemInformation(SystemProcessInformation, &buffer, 0);

  if (NT_SUCCESS(status)) {
    for (myInfos = buffer; callBack(myInfos, pvArg) && myInfos->NextEntryOffset;
         myInfos = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)myInfos +
                                                 myInfos->NextEntryOffset))
      ;
    LocalFree(buffer);
  }
  return status;
}

BOOL CALLBACK mProcessCallbackPIDforName(
    PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg) {
  if (((PMODULE_PROCESS_PID_FOR_NAME)pvArg)->isFound = RtlEqualUnicodeString(
          &pSystemProcessInformation->ImageName,
          ((PMODULE_PROCESS_PID_FOR_NAME)pvArg)->name, TRUE))
    *((PMODULE_PROCESS_PID_FOR_NAME)pvArg)->processId =
        PtrToUlong(pSystemProcessInformation->UniqueProcessId);
  return !((PMODULE_PROCESS_PID_FOR_NAME)pvArg)->isFound;
}

BOOL mGetProcessIDForName(LPCWSTR name, PDWORD processId) {
  BOOL status = FALSE;
  UNICODE_STRING uName;
  MODULE_PROCESS_PID_FOR_NAME mySearch = {&uName, processId, FALSE};

  RtlInitUnicodeString(&uName, name);
  if (NT_SUCCESS(mGetProcessInformation(mProcessCallbackPIDforName, &mySearch)))
    status = mySearch.isFound;
  return status;
}

NTSTATUS mProcessGetMemInfo(PMODULE_MEMORY_HANDLE memory,
                            PMODULE_MEMORY_RANGE_ENUM_CALLBACK callBack,
                            PVOID pvArg) {
  NTSTATUS status = STATUS_NOT_FOUND;
  MEMORY_BASIC_INFORMATION memoryInfos;
  PBYTE currentPage, maxPage;
  PMINIDUMP_MEMORY_INFO_LIST maListeInfo = NULL;
  PMINIDUMP_MEMORY_INFO mesInfos = NULL;
  ULONG i;
  BOOL continueCallback = TRUE;

  if (!NT_SUCCESS(mNTQuerySystemInformation(KIWI_SystemMmSystemRangeStart,
                                            &maxPage, sizeof(PBYTE))))
    maxPage = MmSystemRangeStart;

  switch (memory->type) {
    case MODULE_MEMORY_TYPE_OWN:
      for (currentPage = 0; (currentPage < maxPage) && continueCallback;
           currentPage += memoryInfos.RegionSize)
        if (VirtualQuery(currentPage, &memoryInfos,
                         sizeof(MEMORY_BASIC_INFORMATION)) ==
            sizeof(MEMORY_BASIC_INFORMATION))
          continueCallback = callBack(&memoryInfos, pvArg);
        else
          break;
      status = STATUS_SUCCESS;
      break;
    case MODULE_MEMORY_TYPE_PROCESS:
      for (currentPage = 0; (currentPage < maxPage) && continueCallback;
           currentPage += memoryInfos.RegionSize)
        if (VirtualQueryEx(memory->pHandleProcess->hProcess, currentPage,
                           &memoryInfos, sizeof(MEMORY_BASIC_INFORMATION)) ==
            sizeof(MEMORY_BASIC_INFORMATION))
          continueCallback = callBack(&memoryInfos, pvArg);
        else
          break;
      status = STATUS_SUCCESS;
      break;
    case MODULE_MEMORY_TYPE_PROCESS_DMP:
      if (maListeInfo = (PMINIDUMP_MEMORY_INFO_LIST)mMiniDumpStream(
              memory->pHandleProcessDmp->hMinidump, MemoryInfoListStream)) {
        for (i = 0; (i < maListeInfo->NumberOfEntries) && continueCallback;
             i++) {
          mesInfos = (PMINIDUMP_MEMORY_INFO)((PBYTE)maListeInfo +
                                             maListeInfo->SizeOfHeader +
                                             (i * maListeInfo->SizeOfEntry));
          memoryInfos.AllocationBase = (PVOID)mesInfos->AllocationBase;
          memoryInfos.AllocationProtect = mesInfos->AllocationProtect;
          memoryInfos.BaseAddress = (PVOID)mesInfos->BaseAddress;
          memoryInfos.Protect = mesInfos->Protect;
          memoryInfos.RegionSize = (SIZE_T)mesInfos->RegionSize;
          memoryInfos.State = mesInfos->State;
          memoryInfos.Type = mesInfos->Type;
          continueCallback = callBack(&memoryInfos, pvArg);
        }
        status = STATUS_SUCCESS;
      }
      break;
    default:
      break;
  }

  return status;
}
