#define _WIN32_WINNT 0x0602

#include <windows.h>
#include <userenv.h>
#include <sddl.h>
#include <string>
#include <vector>
#include <iostream>

#include "Logger.h"
#include "EtwMonitor.h"

#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "advapi32.lib")


static void PrintError(const char* msg)
{
    DWORD e = GetLastError();
    LPVOID lpMsgBuf = nullptr;
    FormatMessageA(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, e, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPSTR)&lpMsgBuf, 0, NULL);
    std::cerr << msg << " (error " << e << "): "
        << (lpMsgBuf ? (char*)lpMsgBuf : "unknown") << "\n";
    if (lpMsgBuf) LocalFree(lpMsgBuf);
}


struct CommandLineArgs
{
    std::wstring appPath;
    std::vector<std::wstring> args;
    std::wstring containerName;
    bool forceRecreate;
};

static std::wstring QuoteIfNeeded(const std::wstring& s)
{
    if (s.find(L' ') != std::wstring::npos || s.empty())
        return L"\"" + s + L"\"";
    return s;
}

static std::wstring BuildCommandLine(const std::wstring& appPath, const std::vector<std::wstring>& args)
{
    std::wstring cmdLine = QuoteIfNeeded(appPath);

    for (const auto& arg : args)
    {
        cmdLine += L" ";
        cmdLine += QuoteIfNeeded(arg);
    }

    return cmdLine;
}

static bool ParseCommandLine(int argc, wchar_t* argv[], CommandLineArgs& outArgs)
{
    if (argc < 2)
        return false;
    

    outArgs.forceRecreate = false;
    outArgs.containerName = L"MyAppContainer";

    for (int i = 1; i < argc; ++i)
    {
        std::wstring arg = argv[i];

        if (arg == L"-n" && i + 1 < argc)
        {
            // Custom container name
            outArgs.containerName = argv[++i];
        }
        else if (arg == L"--reset" || arg == L"-r")
        {
            // Force recreate the container
            outArgs.forceRecreate = true;
        }
        else if (arg == L"-h" || arg == L"--help")
        {
            return false;
        }
        else if (outArgs.appPath.empty())
        {
            // First non-flag argument is the app path
            outArgs.appPath = arg;
        }
        else
        {
            // Rest are arguments to the app
            outArgs.args.push_back(arg);
        }
    }

    return !outArgs.appPath.empty();
}


static void DeleteAppContainerProfileIfExists(const std::wstring& containerName)
{
    HRESULT hr = DeleteAppContainerProfile(containerName.c_str());
    if (SUCCEEDED(hr))
    {
        std::wcout << L"[+] Deleted existing AppContainer profile: " << containerName << L"\n";
        // Give Windows time to clean up
        Sleep(200);
    }
}

static PSID CreateOrGetAppContainerSid(const std::wstring& containerName, bool forceRecreate)
{
    PSID pAppContainerSid = nullptr;

    if (forceRecreate)
    {
        DeleteAppContainerProfileIfExists(containerName);
    }

    HRESULT hr = DeriveAppContainerSidFromAppContainerName(containerName.c_str(), &pAppContainerSid);

    if (FAILED(hr))
    {
        // Profile doesn't exist, create it
        if (hr == HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND) || hr == HRESULT_FROM_WIN32(ERROR_NOT_FOUND))
        {
            hr = CreateAppContainerProfile(
                containerName.c_str(),
                containerName.c_str(),
                L"AppContainer created by WinAppSandBox",
                nullptr, 0, &pAppContainerSid);

            if (FAILED(hr))
            {
                std::wcerr << L"[ERROR] CreateAppContainerProfile failed\n";
                PrintError("CreateAppContainerProfile");
                return nullptr;
            }

            std::wcout << L"[+] Created new AppContainer profile: " << containerName << L"\n";


            std::wcout << L"[+] Waiting for profile initialization...\n";
            Sleep(500);
        }
        else
        {
            std::wcerr << L"[ERROR] DeriveAppContainerSidFromAppContainerName failed\n";
            PrintError("DeriveAppContainerSidFromAppContainerName");
            return nullptr;
        }
    }
    else
    {
        std::wcout << L"[+] Using existing AppContainer profile: " << containerName << L"\n";
    }

    LPWSTR sidString = nullptr;
    if (ConvertSidToStringSidW(pAppContainerSid, &sidString))
    {
        std::wcout << L"[+] AppContainer SID: " << sidString << L"\n";
        LocalFree(sidString);
    }

    return pAppContainerSid;
}


static int LaunchInAppContainer(
    const std::wstring& commandLine,
    PSID appContainerSid)
{
    // Set up security capabilities
    SECURITY_CAPABILITIES secCaps{};
    SecureZeroMemory(&secCaps, sizeof(secCaps));
    secCaps.AppContainerSid = appContainerSid;
    secCaps.Capabilities = nullptr;
    secCaps.CapabilityCount = 0;
    secCaps.Reserved = 0;

    SIZE_T attrListSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrListSize);

    LPPROC_THREAD_ATTRIBUTE_LIST attrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(
        GetProcessHeap(), 0, attrListSize);

    if (!attrList)
    {
        PrintError("HeapAlloc for attribute list");
        return 1;
    }

    if (!InitializeProcThreadAttributeList(attrList, 1, 0, &attrListSize))
    {
        PrintError("InitializeProcThreadAttributeList");
        HeapFree(GetProcessHeap(), 0, attrList);
        return 1;
    }

    if (!UpdateProcThreadAttribute(
        attrList, 0,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
        &secCaps, sizeof(secCaps), nullptr, nullptr))
    {
        PrintError("UpdateProcThreadAttribute");
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
        return 1;
    }

    STARTUPINFOEXW siex{};
    PROCESS_INFORMATION pi{};
    ZeroMemory(&siex, sizeof(siex));
    ZeroMemory(&pi, sizeof(pi));
    siex.StartupInfo.cb = sizeof(siex);
    siex.lpAttributeList = attrList;

    std::wstring cmdLineMutable = commandLine;

    std::wcout << L"\n[+] Launching process in AppContainer...\n";
    std::wcout << L"[+] Command Line: " << commandLine << L"\n";

    BOOL created = CreateProcessW(
        nullptr,                                            // MUST be nullptr!
        &cmdLineMutable[0],                                 // Mutable command line
        nullptr,                                            // Process security
        nullptr,                                            // Thread security
        FALSE,                                              // Inherit handles
        EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,  // Flags
        nullptr,                                            // Environment
        nullptr,                                            // Current directory
        &siex.StartupInfo,                                  // Startup info
        &pi);                                               // Process info

    if (!created)
    {
        std::wcerr << L"\n[ERROR] CreateProcessW failed!\n";
        PrintError("CreateProcessW");
        std::wcerr << L"\nTroubleshooting:\n";
        std::wcerr << L"  - Try running with --reset flag to recreate the profile\n";
        std::wcerr << L"  - Try a different container name with -n flag\n";
        std::wcerr << L"  - Example: WinAppSandBox.exe -n FreshContainer <path>\n";
        DeleteProcThreadAttributeList(attrList);
        HeapFree(GetProcessHeap(), 0, attrList);
        return 1;
    }

    std::wcout << L"[SUCCESS] Process launched! PID = " << pi.dwProcessId << L"\n";
    std::wcout << L"[+] Waiting for process to exit...\n\n";

    // Wait for process to complete
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    std::wcout << L"\n[+] Process exited with code: " << exitCode << L"\n";

    // Cleanup
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DeleteProcThreadAttributeList(attrList);
    HeapFree(GetProcessHeap(), 0, attrList);

    return (int)exitCode;
}

static int SandBox(const CommandLineArgs& args)
{
    // Validate file exists
    if (GetFileAttributesW(args.appPath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        std::wcerr << L"[ERROR] File not found: " << args.appPath << L"\n";
        return 1;
    }

    // Create or get AppContainer SID
    PSID appContainerSid = CreateOrGetAppContainerSid(args.containerName, args.forceRecreate);
    if (!appContainerSid)
    {
        return 1;
    }

    // Build full command line
    std::wstring commandLine = BuildCommandLine(args.appPath, args.args);

    // Launch the process
    int exitCode = LaunchInAppContainer(commandLine, appContainerSid);

    // Cleanup SID
    FreeSid(appContainerSid);

    return exitCode;
}

int wmain(int argc, wchar_t* argv[])
{
    std::wcout << L"========================================\n";
    std::wcout << L"  Windows AppContainer Sandbox Tool\n";
    std::wcout << L"========================================\n\n";

    Logger::Init();
    EtwMonitor::Start();
    // Parse command line
    for (int i = 0; i < argc; ++i)
    
        Logger::Log(L"argv[" + std::to_wstring(i) + L"]: " + argv[i]);

    CommandLineArgs cmdArgs;
    if (!ParseCommandLine(argc, argv, cmdArgs))
    {
        std::wcout << L"Usage: WinAppSandBox.exe [options] <programPath> [args...]\n\n";
        std::wcout << L"Options:\n";
        std::wcout << L"  -n <name>     Use custom AppContainer name (default: MyAppContainer)\n";
        std::wcout << L"  --reset, -r   Delete and recreate the AppContainer profile\n";
        std::wcout << L"  -h, --help    Show this help message\n\n";
        std::wcout << L"Examples:\n";
        std::wcout << L"  WinAppSandBox.exe C:\\Windows\\System32\\notepad.exe\n";
        std::wcout << L"  WinAppSandBox.exe C:\\Windows\\System32\\cmd.exe\n";
        std::wcout << L"  WinAppSandBox.exe -n CustomContainer C:\\Windows\\System32\\calc.exe\n";
        std::wcout << L"  WinAppSandBox.exe --reset C:\\Windows\\System32\\cmd.exe\n";
        std::wcout << L"  WinAppSandBox.exe \"C:\\Program Files\\App\\app.exe\" arg1 arg2\n\n";
        std::wcout << L"Troubleshooting:\n";
        std::wcout << L"  If you get 'file not found' errors, try:\n";
        std::wcout << L"  1. Use --reset flag to recreate the profile\n";
        std::wcout << L"  2. Use a different container name with -n flag\n\n";
        return 0;
    }

    // Run in sandbox
    Logger::Shutdown();
    EtwMonitor::Stop();

    return SandBox(cmdArgs);
} 
