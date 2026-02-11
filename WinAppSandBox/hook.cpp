// hook.cpp - Compile x64: cl /LD hook.cpp /I "C:\detours\include" /O2 /link "C:\detours\lib.X64\detours.lib" /subsystem:console
#include "hook.h"
#include <detours.h>
#include <cstdio>
#include <cstdarg>

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "advapi32.lib")

// ============================================================================
// GLOBAL STATE DEFINITIONS
// ============================================================================
HANDLE g_hLogPipe = INVALID_HANDLE_VALUE;
CRITICAL_SECTION g_csLog;
BOOL g_bHooksActive = FALSE;

// ============================================================================
// LOGGING IMPLEMENTATION
// ============================================================================
void LogApi(LPCSTR module, LPCSTR func) {
    LogApi(module, func, "");
}

void LogApi(LPCSTR module, LPCSTR func, LPCSTR fmt, ...) {
    if (g_hLogPipe == INVALID_HANDLE_VALUE) return;

    EnterCriticalSection(&g_csLog);

    char buffer[512];
    int len = _snprintf_s(buffer, _countof(buffer), _TRUNCATE, "%s!%s", module, func);

    if (fmt && fmt[0] != '\0') {
        va_list args;
        va_start(args, fmt);
        len += _vsnprintf_s(buffer + len, _countof(buffer) - len, _TRUNCATE, fmt, args);
        va_end(args);
    }

    if (len < 0) len = 0;
    buffer[len++] = '\n';

    DWORD written;
    WriteFile(g_hLogPipe, buffer, len, &written, NULL);

    LeaveCriticalSection(&g_csLog);
}

// ============================================================================
// HOOK FUNCTION POINTERS (definitions)
// ============================================================================
// File Operations
HANDLE(WINAPI* Real_CreateFileW)(
    LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE) = nullptr;
BOOL(WINAPI* Real_ReadFile)(
    HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED) = nullptr;
NTSTATUS(NTAPI* Real_NtCreateFile)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG) = nullptr;

// Process/Thread
BOOL(WINAPI* Real_CreateProcessW)(
    LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
    BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION) = nullptr;
NTSTATUS(NTAPI* Real_NtOpenProcess)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID) = nullptr;

// Memory
LPVOID(WINAPI* Real_VirtualAlloc)(
    LPVOID, SIZE_T, DWORD, DWORD) = nullptr;
BOOL(WINAPI* Real_WriteProcessMemory)(
    HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*) = nullptr;

// Registry
LSTATUS(WINAPI* Real_RegSetValueExW)(
    HKEY, LPCWSTR, DWORD, DWORD, CONST BYTE*, DWORD) = nullptr;

// Network
int (WINAPI* Real_connect)(
    SOCKET, const struct sockaddr*, int) = nullptr;

// ============================================================================
// HOOK IMPLEMENTATIONS
// ============================================================================
static HANDLE WINAPI Hooked_CreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    HANDLE h = Real_CreateFileW(lpFileName, dwDesiredAccess, dwShareMode,
        lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

    if (h != INVALID_HANDLE_VALUE && lpFileName) {
        LogApi("kernel32", "CreateFileW", " path=\"%ls\" handle=0x%p", lpFileName, h);
    }
    return h;
}

static BOOL WINAPI Hooked_ReadFile(
    HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    BOOL ret = Real_ReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    if (ret && lpNumberOfBytesRead) {
        LogApi("kernel32", "ReadFile", " handle=0x%p bytes=%lu", hFile, *lpNumberOfBytesRead);
    }
    return ret;
}

static NTSTATUS NTAPI Hooked_NtCreateFile(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    NTSTATUS status = Real_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
        AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);

    if (NT_SUCCESS(status) && ObjectAttributes && ObjectAttributes->ObjectName) {
        LogApi("ntdll", "NtCreateFile", " path=\"%wZ\" handle=0x%p",
            ObjectAttributes->ObjectName, FileHandle ? *FileHandle : NULL);
    }
    return status;
}

static BOOL WINAPI Hooked_CreateProcessW(
    LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags,
    LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{
    BOOL ret = Real_CreateProcessW(lpApplicationName, lpCommandLine, lpProcessAttributes,
        lpProcessAttributes, bInheritHandles, dwCreationFlags, lpEnvironment,
        lpCurrentDirectory, lpStartupInfo, lpProcessInformation);

    if (ret && lpProcessInformation) {
        LogApi("kernel32", "CreateProcessW", " pid=%lu tid=%lu",
            lpProcessInformation->dwProcessId,
            lpProcessInformation->dwThreadId);
    }
    return ret;
}

static NTSTATUS NTAPI Hooked_NtOpenProcess(
    PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
    NTSTATUS status = Real_NtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    if (NT_SUCCESS(status) && ProcessHandle && ClientId) {
        DWORD pid = (DWORD)(ULONG_PTR)ClientId->UniqueProcess;
        LogApi("ntdll", "NtOpenProcess", " pid=%lu handle=0x%p", pid, *ProcessHandle);
    }
    return status;
}

static LPVOID WINAPI Hooked_VirtualAlloc(
    LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
    LPVOID ptr = Real_VirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
    if (ptr) {
        LogApi("kernel32", "VirtualAlloc", " addr=0x%p size=0x%zx prot=0x%lx", ptr, dwSize, flProtect);
    }
    return ptr;
}

static BOOL WINAPI Hooked_WriteProcessMemory(
    HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
{
    BOOL ret = Real_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    if (ret) {
        DWORD pid = GetProcessId(hProcess);
        LogApi("kernel32", "WriteProcessMemory", " pid=%lu addr=0x%p size=0x%zx", pid, lpBaseAddress, nSize);
    }
    return ret;
}

static LSTATUS WINAPI Hooked_RegSetValueExW(
    HKEY hKey, LPCWSTR lpValueName, DWORD Reserved, DWORD dwType, CONST BYTE* lpData, DWORD cbData)
{
    LSTATUS ret = Real_RegSetValueExW(hKey, lpValueName, Reserved, dwType, lpData, cbData);
    if (ret == ERROR_SUCCESS && lpValueName) {
        LogApi("advapi32", "RegSetValueExW", " value=\"%ls\" type=%lu size=%lu", lpValueName, dwType, cbData);
    }
    return ret;
}

static int WINAPI Hooked_connect(
    SOCKET s, const struct sockaddr* name, int namelen)
{
    int ret = Real_connect(s, name, namelen);
    if (ret == 0 && name && name->sa_family == AF_INET) {
        struct sockaddr_in* sin = (struct sockaddr_in*)name;
        char ip[16];
        _snprintf_s(ip, _countof(ip), "%u.%u.%u.%u",
            (unsigned char)sin->sin_addr.S_un.S_un_b.s_b1,
            (unsigned char)sin->sin_addr.S_un.S_un_b.s_b2,
            (unsigned char)sin->sin_addr.S_un.S_un_b.s_b3,
            (unsigned char)sin->sin_addr.S_un.S_un_b.s_b4);
        LogApi("ws2_32", "connect", " ip=%s port=%u", ip, ntohs(sin->sin_port));
    }
    return ret;
}

// ============================================================================
// HOOK INSTALLATION / CLEANUP
// ============================================================================
void InstallHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Only hook modules already loaded
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    HMODULE hAdvapi32 = GetModuleHandleA("advapi32.dll");
    HMODULE hWs2_32 = GetModuleHandleA("ws2_32.dll");

    if (hKernel32) {
        Real_CreateFileW = (decltype(Real_CreateFileW))GetProcAddress(hKernel32, "CreateFileW");
        if (Real_CreateFileW) DetourAttach(&(PVOID&)Real_CreateFileW, Hooked_CreateFileW);

        Real_ReadFile = (decltype(Real_ReadFile))GetProcAddress(hKernel32, "ReadFile");
        if (Real_ReadFile) DetourAttach(&(PVOID&)Real_ReadFile, Hooked_ReadFile);

        Real_CreateProcessW = (decltype(Real_CreateProcessW))GetProcAddress(hKernel32, "CreateProcessW");
        if (Real_CreateProcessW) DetourAttach(&(PVOID&)Real_CreateProcessW, Hooked_CreateProcessW);

        Real_VirtualAlloc = (decltype(Real_VirtualAlloc))GetProcAddress(hKernel32, "VirtualAlloc");
        if (Real_VirtualAlloc) DetourAttach(&(PVOID&)Real_VirtualAlloc, Hooked_VirtualAlloc);

        Real_WriteProcessMemory = (decltype(Real_WriteProcessMemory))GetProcAddress(hKernel32, "WriteProcessMemory");
        if (Real_WriteProcessMemory) DetourAttach(&(PVOID&)Real_WriteProcessMemory, Hooked_WriteProcessMemory);
    }

    if (hNtdll) {
        Real_NtCreateFile = (decltype(Real_NtCreateFile))GetProcAddress(hNtdll, "NtCreateFile");
        if (Real_NtCreateFile) DetourAttach(&(PVOID&)Real_NtCreateFile, Hooked_NtCreateFile);

        Real_NtOpenProcess = (decltype(Real_NtOpenProcess))GetProcAddress(hNtdll, "NtOpenProcess");
        if (Real_NtOpenProcess) DetourAttach(&(PVOID&)Real_NtOpenProcess, Hooked_NtOpenProcess);
    }

    if (hAdvapi32) {
        Real_RegSetValueExW = (decltype(Real_RegSetValueExW))GetProcAddress(hAdvapi32, "RegSetValueExW");
        if (Real_RegSetValueExW) DetourAttach(&(PVOID&)Real_RegSetValueExW, Hooked_RegSetValueExW);
    }

    if (hWs2_32) {
        Real_connect = (decltype(Real_connect))GetProcAddress(hWs2_32, "connect");
        if (Real_connect) DetourAttach(&(PVOID&)Real_connect, Hooked_connect);
    }

    LONG err = DetourTransactionCommit();
    if (err == NO_ERROR) {
        g_bHooksActive = TRUE;
        LogApi("hook", "InstallHooks", " SUCCESS - 9 hooks active");
    }
    else {
        LogApi("hook", "InstallHooks", " FAILED error=%ld", err);
    }
}

void RemoveHooks() {
    if (!g_bHooksActive) return;

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    if (Real_CreateFileW) DetourDetach(&(PVOID&)Real_CreateFileW, Hooked_CreateFileW);
    if (Real_ReadFile) DetourDetach(&(PVOID&)Real_ReadFile, Hooked_ReadFile);
    if (Real_CreateProcessW) DetourDetach(&(PVOID&)Real_CreateProcessW, Hooked_CreateProcessW);
    if (Real_VirtualAlloc) DetourDetach(&(PVOID&)Real_VirtualAlloc, Hooked_VirtualAlloc);
    if (Real_WriteProcessMemory) DetourDetach(&(PVOID&)Real_WriteProcessMemory, Hooked_WriteProcessMemory);

    if (Real_NtCreateFile) DetourDetach(&(PVOID&)Real_NtCreateFile, Hooked_NtCreateFile);
    if (Real_NtOpenProcess) DetourDetach(&(PVOID&)Real_NtOpenProcess, Hooked_NtOpenProcess);

    if (Real_RegSetValueExW) DetourDetach(&(PVOID&)Real_RegSetValueExW, Hooked_RegSetValueExW);

    if (Real_connect) DetourDetach(&(PVOID&)Real_connect, Hooked_connect);

    DetourTransactionCommit();
    g_bHooksActive = FALSE;
    LogApi("hook", "RemoveHooks", " complete");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    switch (dwReason) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_csLog);

        // Connect to monitoring pipe
        g_hLogPipe = CreateFileW(
            LOG_PIPE_NAME,
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (g_hLogPipe == INVALID_HANDLE_VALUE) {
            OutputDebugStringA("[HOOK] ERROR: Could not connect to log pipe - aborting injection\n");
            DeleteCriticalSection(&g_csLog);
            return FALSE;
        }

        // Suspend other threads ONLY if multi-threaded process
        DWORD myTid = GetCurrentThreadId();
        DWORD myPid = GetCurrentProcessId();
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        DWORD threadCount = 1;  // Count ourselves

        if (hSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te = { sizeof(THREADENTRY32) };
            if (Thread32First(hSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID == myPid) threadCount++;
                } while (Thread32Next(hSnap, &te));
            }
            CloseHandle(hSnap);
        }

        if (threadCount > 1) {
            hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                THREADENTRY32 te = { sizeof(THREADENTRY32) };
                if (Thread32First(hSnap, &te)) {
                    do {
                        if (te.th32OwnerProcessID == myPid && te.th32ThreadID != myTid) {
                            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                            if (hThread) {
                                SuspendThread(hThread);
                                CloseHandle(hThread);
                            }
                        }
                    } while (Thread32Next(hSnap, &te));
                }
                CloseHandle(hSnap);
            }
        }

        // Install hooks AFTER suspending threads
        InstallHooks();

        // Resume threads if we suspended them
        if (threadCount > 1) {
            hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                THREADENTRY32 te = { sizeof(THREADENTRY32) };
                if (Thread32First(hSnap, &te)) {
                    do {
                        if (te.th32OwnerProcessID == myPid && te.th32ThreadID != myTid) {
                            HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                            if (hThread) {
                                ResumeThread(hThread);
                                CloseHandle(hThread);
                            }
                        }
                    } while (Thread32Next(hSnap, &te));
                }
                CloseHandle(hSnap);
            }
        }

        break;
    }

    case DLL_PROCESS_DETACH:
        if (g_bHooksActive) {
            RemoveHooks();
        }
        if (g_hLogPipe != INVALID_HANDLE_VALUE) {
            CloseHandle(g_hLogPipe);
        }
        DeleteCriticalSection(&g_csLog);
        break;
    }
    return TRUE;
}