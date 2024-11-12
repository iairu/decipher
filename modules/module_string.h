#pragma once

#include "../src/globals.h"

typedef CONST char *PCSZ;
typedef STRING ANSI_STRING;
typedef PSTRING PANSI_STRING;
typedef PSTRING PCANSI_STRING;

typedef STRING OEM_STRING;
typedef PSTRING POEM_STRING;
typedef CONST STRING *PCOEM_STRING;
typedef CONST UNICODE_STRING *PCUNICODE_STRING;

#define DECLARE_UNICODE_STRING(_var, _string)                              \
  const WCHAR _var##_buffer[] = _string;                                   \
  UNICODE_STRING _var = {sizeof(_string) - sizeof(WCHAR), sizeof(_string), \
                         (PWCH)_var##_buffer}

extern VOID WINAPI RtlInitString(OUT PSTRING DestinationString,
                                 IN PCSZ SourceString);
extern VOID WINAPI RtlInitUnicodeString(OUT PUNICODE_STRING DestinationString,
                                        IN PCWSTR SourceString);

extern NTSTATUS WINAPI RtlAnsiStringToUnicodeString(
    OUT PUNICODE_STRING DestinationString, IN PCANSI_STRING SourceString,
    IN BOOLEAN AllocateDestinationString);
extern NTSTATUS WINAPI RtlUnicodeStringToAnsiString(
    OUT PANSI_STRING DestinationString, IN PCUNICODE_STRING SourceString,
    IN BOOLEAN AllocateDestinationString);

extern VOID WINAPI RtlUpperString(OUT PSTRING DestinationString,
                                  IN const STRING *SourceString);
extern NTSTATUS WINAPI RtlUpcaseUnicodeString(
    IN OUT PUNICODE_STRING DestinationString, IN PCUNICODE_STRING SourceString,
    IN BOOLEAN AllocateDestinationString);
extern NTSTATUS WINAPI RtlDowncaseUnicodeString(
    PUNICODE_STRING DestinationString, IN PCUNICODE_STRING SourceString,
    IN BOOLEAN AllocateDestinationString);
extern WCHAR WINAPI RtlUpcaseUnicodeChar(IN WCHAR SourceCharacter);

extern BOOLEAN WINAPI RtlEqualString(IN const STRING *String1,
                                     IN const STRING *String2,
                                     IN BOOLEAN CaseInSensitive);
extern BOOLEAN WINAPI RtlEqualUnicodeString(IN PCUNICODE_STRING String1,
                                            IN PCUNICODE_STRING String2,
                                            IN BOOLEAN CaseInSensitive);

extern LONG WINAPI RtlCompareUnicodeString(IN PCUNICODE_STRING String1,
                                           IN PCUNICODE_STRING String2,
                                           IN BOOLEAN CaseInSensitive);
extern LONG WINAPI RtlCompareString(IN const STRING *String1,
                                    IN const STRING *String2,
                                    IN BOOLEAN CaseInSensitive);

extern VOID WINAPI RtlFreeAnsiString(IN PANSI_STRING AnsiString);
extern VOID WINAPI RtlFreeUnicodeString(IN PUNICODE_STRING UnicodeString);

extern NTSTATUS WINAPI RtlStringFromGUID(IN LPCGUID Guid,
                                         PUNICODE_STRING UnicodeString);
extern NTSTATUS WINAPI RtlGUIDFromString(IN PCUNICODE_STRING GuidString,
                                         OUT GUID *Guid);
extern NTSTATUS NTAPI
RtlValidateUnicodeString(IN ULONG Flags, IN PCUNICODE_STRING UnicodeString);

extern NTSTATUS WINAPI RtlAppendUnicodeStringToString(
    IN OUT PUNICODE_STRING Destination, IN PCUNICODE_STRING Source);

extern VOID NTAPI RtlRunDecodeUnicodeString(IN BYTE Hash,
                                            IN OUT PUNICODE_STRING String);
extern VOID NTAPI RtlRunEncodeUnicodeString(IN OUT PBYTE Hash,
                                            IN OUT PUNICODE_STRING String);

BOOL mStringArgsByName(const int argc, const wchar_t *argv[],
                       const wchar_t *name, const wchar_t **theArgs,
                       const wchar_t *defaultValue);
