#pragma once

#include <userenv.h>

#include "../src/globals.h"
#include "module_memory.h"
#include "module_string.h"

#ifdef _M_X64
#define MmSystemRangeStart ((PBYTE)0xffff080000000000)
#elif defined _M_IX86
#define MmSystemRangeStart ((PBYTE)0x80000000)
#endif

#define __MACHINE(X) X;
#define __MACHINEX86 __MACHINE
__MACHINEX86(unsigned long __readfsdword(unsigned long))

typedef enum _SYSTEM_INFORMATION_CLASS {
  SystemBasicInformation,
  SystemProcessorInformation,
  SystemPerformanceInformation,
  SystemTimeOfDayInformation,
  SystemPathInformation,
  SystemProcessInformation,
  SystemCallCountInformation,
  SystemDeviceInformation,
  SystemProcessorPerformanceInformation,
  SystemFlagsInformation,
  SystemCallTimeInformation,
  SystemModuleInformation,
  SystemLocksInformation,
  SystemStackTraceInformation,
  SystemPagedPoolInformation,
  SystemNonPagedPoolInformation,
  SystemHandleInformation,
  SystemObjectInformation,
  SystemPageFileInformation,
  SystemVdmInstemulInformation,
  SystemVdmBopInformation,
  SystemFileCacheInformation,
  SystemPoolTagInformation,
  SystemInterruptInformation,
  SystemDpcBehaviorInformation,
  SystemFullMemoryInformation,
  SystemLoadGdiDriverInformation,
  SystemUnloadGdiDriverInformation,
  SystemTimeAdjustmentInformation,
  SystemSummaryMemoryInformation,
  SystemNextEventIdInformation,
  SystemEventIdsInformation,
  SystemCrashDumpInformation,
  SystemExceptionInformation,
  SystemCrashDumpStateInformation,
  SystemKernelDebuggerInformation,
  SystemContextSwitchInformation,
  SystemRegistryQuotaInformation,
  SystemExtendServiceTableInformation,
  SystemPrioritySeperation,
  SystemPlugPlayBusInformation,
  SystemDockInformation,
  KIWI_SystemPowerInformation,
  SystemProcessorSpeedInformation,
  SystemCurrentTimeZoneInformation,
  SystemLookasideInformation,
  KIWI_SystemMmSystemRangeStart = 50
} SYSTEM_INFORMATION_CLASS,
    *PSYSTEM_INFORMATION_CLASS;

typedef enum _PROCESSINFOCLASS {
  ProcessBasicInformation,
  ProcessQuotaLimits,
  ProcessIoCounters,
  ProcessVmCounters,
  ProcessTimes,
  ProcessBasePriority,
  ProcessRaisePriority,
  ProcessDebugPort,
  ProcessExceptionPort,
  ProcessAccessToken,
  ProcessLdtInformation,
  ProcessLdtSize,
  ProcessDefaultHardErrorMode,
  ProcessIoPortHandlers,  // kernel mode only
  ProcessPooledUsageAndLimits,
  ProcessWorkingSetWatch,
  ProcessUserModeIOPL,
  ProcessEnableAlignmentFaultFixup,
  ProcessPriorityClass,
  ProcessWx86Information,
  ProcessHandleCount,
  ProcessAffinityMask,
  ProcessPriorityBoost,
  ProcessDeviceMap,
  ProcessSessionInformation,
  ProcessForegroundInformation,
  ProcessWow64Information,
  ProcessImageFileName,
  ProcessLUIDDeviceMapsEnabled,
  ProcessBreakOnTermination,
  ProcessDebugObjectHandle,
  ProcessDebugFlags,
  ProcessHandleTracing,
  ProcessIoPriority,
  ProcessExecuteFlags,
  ProcessTlsInformation,
  ProcessCookie,
  ProcessImageInformation,
  ProcessCycleTime,
  ProcessPagePriority,
  ProcessInstrumentationCallback,
  ProcessThreadStackAllocation,
  ProcessWorkingSetWatchEx,
  ProcessImageFileNameWin32,
  ProcessImageFileMapping,
  ProcessAffinityUpdateMode,
  ProcessMemoryAllocationMode,
  ProcessGroupInformation,
  ProcessTokenVirtualizationEnabled,
  ProcessConsoleHostProcess,
  ProcessWindowInformation,
  MaxProcessInfoClass
} PROCESSINFOCLASS;

typedef LONG KPRIORITY;

typedef struct _VM_COUNTERS {
  SIZE_T PeakVirtualSize;
  SIZE_T VirtualSize;
  ULONG PageFaultCount;
  SIZE_T PeakWorkingSetSize;
  SIZE_T WorkingSetSize;
  SIZE_T QuotaPeakPagedPoolUsage;
  SIZE_T QuotaPagedPoolUsage;
  SIZE_T QuotaPeakNonPagedPoolUsage;
  SIZE_T QuotaNonPagedPoolUsage;
  SIZE_T PagefileUsage;
  SIZE_T PeakPagefileUsage;
} VM_COUNTERS;
typedef VM_COUNTERS *PVM_COUNTERS;

typedef struct _CLIENT_ID {
  PVOID UniqueProcess;
  PVOID UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef enum _KWAIT_REASON {
  Executive,
  FreePage,
  PageIn,
  PoolAllocation,
  DelayExecution,
  Suspended,
  UserRequest,
  WrExecutive,
  WrFreePage,
  WrPageIn,
  WrPoolAllocation,
  WrDelayExecution,
  WrSuspended,
  WrUserRequest,
  WrEventPair,
  WrQueue,
  WrLpcReceive,
  WrLpcReply,
  WrVirtualMemory,
  WrPageOut,
  WrRendezvous,
  WrKeyedEvent,
  WrTerminated,
  WrProcessInSwap,
  WrCpuRateControl,
  WrCalloutStack,
  WrKernel,
  WrResource,
  WrPushLock,
  WrMutex,
  WrQuantumEnd,
  WrDispatchInt,
  WrPreempted,
  WrYieldExecution,
  WrFastMutex,
  WrGuardedMutex,
  WrRundown,
  MaximumWaitReason
} KWAIT_REASON;

typedef struct _SYSTEM_THREAD {
#ifndef _M_X64
  LARGE_INTEGER KernelTime;
#endif
  LARGE_INTEGER UserTime;
  LARGE_INTEGER CreateTime;
  ULONG WaitTime;
  PVOID StartAddress;
  CLIENT_ID ClientId;
  KPRIORITY Priority;
  LONG BasePriority;
  ULONG ContextSwitchCount;
  ULONG State;
  KWAIT_REASON WaitReason;
#ifdef _M_X64
  LARGE_INTEGER unk;
#endif
} SYSTEM_THREAD, *PSYSTEM_THREAD;

typedef struct _SYSTEM_BASIC_INFORMATION {
  ULONG Reserved;
  ULONG TimerResolution;
  ULONG PageSize;
  ULONG NumberOfPhysicalPages;
  ULONG LowestPhysicalPageNumber;
  ULONG HighestPhysicalPageNumber;
  ULONG AllocationGranularity;
  ULONG MinimumUserModeAddress;
  ULONG MaximumUserModeAddress;
  ULONG ActiveProcessorsAffinityMask;
  UCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
  ULONG NextEntryOffset;
  ULONG NumberOfThreads;
  LARGE_INTEGER Reserved[3];
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER UserTime;
  LARGE_INTEGER KernelTime;
  UNICODE_STRING ImageName;
  KPRIORITY BasePriority;
  HANDLE UniqueProcessId;
  HANDLE ParentProcessId;
  ULONG HandleCount;
  LPCWSTR Reserved2[2];
  ULONG PrivatePageCount;
  VM_COUNTERS VirtualMemoryCounters;
  IO_COUNTERS IoCounters;
  SYSTEM_THREAD Threads[ANYSIZE_ARRAY];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef struct _LDR_DATA_TABLE_ENTRY {
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  /// ...
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
  ULONG Length;
  BOOLEAN Initialized;
  PVOID SsHandle;
  LIST_ENTRY InLoadOrderModulevector;
  LIST_ENTRY InMemoryOrderModulevector;
  LIST_ENTRY InInitializationOrderModulevector;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
  BOOLEAN InheritedAddressSpace;
  BOOLEAN ReadImageFileExecOptions;
  BOOLEAN BeingDebugged;
  struct BitField {
    BYTE ImageUsesLargePages : 1;
    BYTE SpareBits : 7;
  };
  HANDLE Mutant;
  PVOID ImageBaseAddress;
  PPEB_LDR_DATA Ldr;
  /// ...
} PEB, *PPEB;

#ifdef _M_X64
typedef struct _LSA_UNICODE_STRING_F32 {
  USHORT Length;
  USHORT MaximumLength;
  DWORD Buffer;
} LSA_UNICODE_STRING_F32, *PLSA_UNICODE_STRING_F32;

typedef LSA_UNICODE_STRING_F32 UNICODE_STRING_F32, *PUNICODE_STRING_F32;

typedef struct _LDR_DATA_TABLE_ENTRY_F32 {
  LIST_ENTRY32 InLoadOrderLinks;
  LIST_ENTRY32 InMemoryOrderLinks;
  LIST_ENTRY32 InInitializationOrderLinks;
  DWORD DllBase;
  DWORD EntryPoint;
  DWORD SizeOfImage;
  UNICODE_STRING_F32 FullDllName;
  UNICODE_STRING_F32 BaseDllName;
  /// ...
} LDR_DATA_TABLE_ENTRY_F32, *PLDR_DATA_TABLE_ENTRY_F32;

typedef struct _PEB_LDR_DATA_F32 {
  ULONG Length;
  BOOLEAN Initialized;
  DWORD SsHandle;
  LIST_ENTRY32 InLoadOrderModulevector;
  LIST_ENTRY32 InMemoryOrderModulevector;
  LIST_ENTRY32 InInitializationOrderModulevector;
} PEB_LDR_DATA_F32, *PPEB_LDR_DATA_F32;

typedef struct _PEB_F32 {
  BOOLEAN InheritedAddressSpace;
  BOOLEAN ReadImageFileExecOptions;
  BOOLEAN BeingDebugged;
  struct BitField_F32 {
    BYTE ImageUsesLargePages : 1;
    BYTE SpareBits : 7;
  };
  DWORD Mutant;
  DWORD ImageBaseAddress;
  DWORD Ldr;
  /// ...
} PEB_F32, *PPEB_F32;
#endif

typedef struct _KERNEL_USER_TIMES {
  LARGE_INTEGER CreateTime;
  LARGE_INTEGER ExitTime;
  LARGE_INTEGER KernelTime;
  LARGE_INTEGER UserTime;
} KERNEL_USER_TIMES, *PKERNEL_USER_TIMES;

typedef struct _PROCESS_BASIC_INFORMATION {
  NTSTATUS ExitStatus;
  PPEB PebBaseAddress;
  ULONG_PTR AffinityMask;
  KPRIORITY BasePriority;
  ULONG_PTR UniqueProcessId;
  ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
  HANDLE Section;
  PVOID MappedBase;
  PVOID ImageBase;
  ULONG ImageSize;
  ULONG Flags;
  USHORT LoadOrderIndex;
  USHORT InitOrderIndex;
  USHORT LoadCount;
  USHORT OffsetToFileName;
  UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
  ULONG NumberOfModules;
  RTL_PROCESS_MODULE_INFORMATION Modules[ANYSIZE_ARRAY];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

extern NTSTATUS WINAPI NtQuerySystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation, IN ULONG SystemInformationLength,
    OUT OPTIONAL PULONG ReturnLength);
extern NTSTATUS WINAPI NtSetSystemInformation(
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    IN PVOID SystemInformation, IN ULONG SystemInformationLength);
extern NTSTATUS WINAPI NtQueryInformationProcess(
    IN HANDLE ProcessHandle, IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID ProcessInformation, OUT ULONG ProcessInformationLength,
    OUT OPTIONAL PULONG ReturnLength);
extern NTSTATUS WINAPI NtSuspendProcess(IN HANDLE ProcessHandle);
extern NTSTATUS WINAPI NtResumeProcess(IN HANDLE ProcessHandle);
extern NTSTATUS WINAPI NtTerminateProcess(IN OPTIONAL HANDLE ProcessHandle,
                                          IN NTSTATUS ExitStatus);

extern PPEB WINAPI RtlGetCurrentPeb();
extern NTSTATUS WINAPI RtlAdjustPrivilege(IN ULONG Privilege, IN BOOL Enable,
                                          IN BOOL CurrentThread,
                                          OUT PULONG pPreviousState);
extern NTSTATUS WINAPI RtlCreateUserThread(
    IN HANDLE Process,
    IN OPTIONAL PSECURITY_DESCRIPTOR ThreadSecurityDescriptor, IN CHAR Flags,
    IN OPTIONAL ULONG ZeroBits, IN OPTIONAL SIZE_T MaximumStackSize,
    IN OPTIONAL SIZE_T CommittedStackSize,
    IN OPTIONAL PTHREAD_START_ROUTINE StartAddress, IN OPTIONAL PVOID Parameter,
    OUT OPTIONAL PHANDLE Thread, OUT OPTIONAL PCLIENT_ID ClientId);

typedef struct _MODULE_PROCESS_VERY_BASIC_MODULE_INFORMATION {
  MODULE_MEMORY_ADDRESS DllBase;
  ULONG SizeOfImage;
  ULONG TimeDateStamp;
  PCUNICODE_STRING NameDontUseOutsideCallback;
} MODULE_PROCESS_VERY_BASIC_MODULE_INFORMATION,
    *PMODULE_PROCESS_VERY_BASIC_MODULE_INFORMATION;

typedef struct _MODULE_PROCESS_PID_FOR_NAME {
  PCUNICODE_STRING name;
  PDWORD processId;
  BOOL isFound;
} MODULE_PROCESS_PID_FOR_NAME, *PMODULE_PROCESS_PID_FOR_NAME;

typedef struct _MODULE_PROCESS_VERY_BASIC_MODULE_INFORMATION_FOR_NAME {
  PCUNICODE_STRING name;
  PMODULE_PROCESS_VERY_BASIC_MODULE_INFORMATION informations;
  BOOL isFound;
} MODULE_PROCESS_VERY_BASIC_MODULE_INFORMATION_FOR_NAME,
    *PMODULE_PROCESS_VERY_BASIC_MODULE_INFORMATION_FOR_NAME;

NTSTATUS mNTQuerySystemInformation(SYSTEM_INFORMATION_CLASS informationClass,
                                   PVOID buffer, ULONG informationLength);
typedef BOOL(CALLBACK *PMODULE_PROCESS_ENUM_CALLBACK)(
    PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
NTSTATUS mGetProcessInformation(PMODULE_PROCESS_ENUM_CALLBACK callBack,
                                PVOID pvArg);
BOOL CALLBACK mProcessCallbackPIDforName(
    PSYSTEM_PROCESS_INFORMATION pSystemProcessInformation, PVOID pvArg);
BOOL mGetProcessIDForName(LPCWSTR name, PDWORD processId);

typedef BOOL(CALLBACK *PMODULE_MODULE_ENUM_CALLBACK)(
    PMODULE_PROCESS_VERY_BASIC_MODULE_INFORMATION pModuleInformation,
    PVOID pvArg);

typedef struct _MODULE_PROCESS_EXPORTED_ENTRY {
  WORD machine;
  DWORD ordinal;
  DWORD hint;
  PSTR name;
  PSTR redirect;
  MODULE_MEMORY_ADDRESS pRva;
  MODULE_MEMORY_ADDRESS function;
} MODULE_PROCESS_EXPORTED_ENTRY, *PMODULE_PROCESS_EXPORTED_ENTRY;
typedef BOOL(CALLBACK *PMODULE_EXPORTED_ENTRY_ENUM_CALLBACK)(
    PMODULE_PROCESS_EXPORTED_ENTRY pExportedEntryInformations, PVOID pvArg);

typedef struct _MODULE_PROCESS_IMPORTED_ENTRY {
  WORD machine;
  PSTR libname;
  DWORD ordinal;
  PSTR name;
  MODULE_MEMORY_ADDRESS pFunction;
  MODULE_MEMORY_ADDRESS function;
} MODULE_PROCESS_IMPORTED_ENTRY, *PMODULE_PROCESS_IMPORTED_ENTRY;
typedef BOOL(CALLBACK *PMODULE_IMPORTED_ENTRY_ENUM_CALLBACK)(
    PMODULE_PROCESS_IMPORTED_ENTRY pImportedEntryInformations, PVOID pvArg);

typedef BOOL(CALLBACK *PMODULE_MEMORY_RANGE_ENUM_CALLBACK)(
    PMEMORY_BASIC_INFORMATION pMemoryBasicInformation, PVOID pvArg);
NTSTATUS mProcessGetMemInfo(PMODULE_MEMORY_HANDLE memory,
                            PMODULE_MEMORY_RANGE_ENUM_CALLBACK callBack,
                            PVOID pvArg);

typedef enum _MODULE_PROCESS_CREATE_TYPE {
  MODULE_PROCESS_CREATE_NORMAL,
  MODULE_PROCESS_CREATE_USER,
  // MODULE_PROCESS_CREATE_TOKEN,
  MODULE_PROCESS_CREATE_LOGON,
} MODULE_PROCESS_CREATE_TYPE;
