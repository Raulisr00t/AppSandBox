// hook.h - Robust API hooking framework declarations
#pragma once

// ============================================================================
// CRITICAL: MUST define _WIN32_WINNT BEFORE any Windows headers
// ============================================================================
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601  // Windows 7+ (required for CLIENT_ID)
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <WinSock2.h>
#include <TlHelp32.h>

#pragma comment(lib,"ws2_32")

#define _countof(array) (sizeof(array) / sizeof(array[0]))

// ============================================================================
// NT TYPE FORWARD DECLARATIONS (avoid redefinitions)
// ============================================================================
// These MUST come BEFORE winternl.h to prevent conflicts
typedef struct _IO_STATUS_BLOCK IO_STATUS_BLOCK;
typedef struct _OBJECT_ATTRIBUTES OBJECT_ATTRIBUTES;
typedef struct _CLIENT_ID CLIENT_ID;

typedef IO_STATUS_BLOCK* PIO_STATUS_BLOCK;
typedef OBJECT_ATTRIBUTES* POBJECT_ATTRIBUTES;
typedef CLIENT_ID* PCLIENT_ID;

// ============================================================================
// Include winternl.h AFTER forward declarations to get full definitions
// ============================================================================
#include <winternl.h>

// ============================================================================
// SAFETY CHECKS: Verify types are properly defined
// ============================================================================
#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

// ============================================================================
// GLOBAL STATE (extern declarations)
// ============================================================================
extern HANDLE g_hLogPipe;
extern CRITICAL_SECTION g_csLog;
extern BOOL g_bHooksActive;

#define LOG_PIPE_NAME L"\\\\.\\pipe\\apihook_log"

// ============================================================================
// LOGGING API
// ============================================================================
void LogApi(LPCSTR module, LPCSTR func);
void LogApi(LPCSTR module, LPCSTR func, LPCSTR fmt, ...);

// ============================================================================
// HOOK FUNCTION PROTOTYPES (extern declarations)
// ============================================================================
// File Operations
extern decltype(&CreateFileW) Real_CreateFileW;
extern decltype(&ReadFile) Real_ReadFile;
extern NTSTATUS(NTAPI* Real_NtCreateFile)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);

// Process/Thread
extern decltype(&CreateProcessW) Real_CreateProcessW;
extern NTSTATUS(NTAPI* Real_NtOpenProcess)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);

// Memory
extern decltype(&VirtualAlloc) Real_VirtualAlloc;
extern decltype(&WriteProcessMemory) Real_WriteProcessMemory;

// Registry
extern decltype(&RegSetValueExW) Real_RegSetValueExW;

// Network
extern int (WINAPI* Real_connect)(
    SOCKET, const struct sockaddr*, int);

// ============================================================================
// HOOK INSTALLATION API
// ============================================================================
void InstallHooks();
void RemoveHooks();