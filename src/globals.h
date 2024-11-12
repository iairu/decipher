#pragma once

#include <ntstatus.h>
#define WIN32_NO_STATUS
#define SECURITY_WIN32
#define CINTERFACE
#define COBJMACROS
#include <windows.h>
#include <sspi.h>
#include <sddl.h>
#include <wincred.h>
#include <ntsecapi.h>
#include <ntsecpkg.h>
#include <stdio.h>
#include <wchar.h>
#include "../modules/module_output.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

#ifndef PRINT_ERROR
#define PRINT_ERROR(...) (mEcho(L"ERROR " TEXT(__FUNCTION__) L" ; " __VA_ARGS__))
#endif

#ifndef PRINT_ERROR_AUTO
#define PRINT_ERROR_AUTO(func) (mEcho(L"ERROR " TEXT(__FUNCTION__) L" ; " func L" (0x%08x)\n", GetLastError()))
#endif

#ifndef W00T
#define W00T(...) (mEcho(TEXT(__FUNCTION__) L" w00t! ; " __VA_ARGS__))
#endif

#define RANSOM_PUBKEY_FILE	L"00000000.pky"
#define RANSOM_PRIKEY_FILE	L"00000000.dky"
#define RANSOM_FILE_EXT		L".WNCRY"