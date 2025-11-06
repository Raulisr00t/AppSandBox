#include <windows.h>
#include <networkisolation.h>
#include <sddl.h>         
#include <iostream>
#include <vector>

void ListAppSandBox() {
    DWORD flags = 0;
    DWORD count = 0;
    PINET_FIREWALL_APP_CONTAINER pContainers = nullptr;

    HMODULE hMod = LoadLibrary(L"FirewallAPI.dll");

    if (!hMod) {
        std::wcerr << L"Failed to load FirewallAPI.dll\n";
        return ;
    }

    auto pEnum = reinterpret_cast<decltype(&NetworkIsolationEnumAppContainers)>(
        GetProcAddress(hMod, "NetworkIsolationEnumAppContainers"));
    auto pFree = reinterpret_cast<decltype(&NetworkIsolationFreeAppContainers)>(
        GetProcAddress(hMod, "NetworkIsolationFreeAppContainers"));

    if (!pEnum || !pFree) {
        std::wcerr << L"Failed to get function addresses\n";
        FreeLibrary(hMod);
        return ;
    }

    int result = pEnum(flags, &count, &pContainers);

    if (result != ERROR_SUCCESS) {
        std::wcerr << L"NetworkIsolationEnumAppContainers failed: " << result << L"\n";
        FreeLibrary(hMod);
        return ;
    }

    std::wcout << L"Found " << count << L" AppContainers:\n";

    for (int i = 1; i < count; i++) {
        auto& c = pContainers[i];

        LPWSTR appSidStr = nullptr;
        LPWSTR userSidStr = nullptr;

        if (c.appContainerSid)
            ConvertSidToStringSid(c.appContainerSid, &appSidStr);
        if (c.userSid)
            ConvertSidToStringSid(c.userSid, &userSidStr);

        std::wcout << L"--------------------------------------------\n";
        std::wcout << L"Container " << i << L":\n";
        std::wcout << L"  AppContainerName: " << (c.appContainerName ? c.appContainerName : L"(null)") << L"\n";
        std::wcout << L"  DisplayName: " << (c.displayName ? c.displayName : L"(null)") << L"\n";
        std::wcout << L"  Description: " << (c.description ? c.description : L"(null)") << L"\n";
        std::wcout << L"  WorkingDirectory: " << (c.workingDirectory ? c.workingDirectory : L"(null)") << L"\n";
        std::wcout << L"  PackageFullName: " << (c.packageFullName ? c.packageFullName : L"(null)") << L"\n";
        std::wcout << L"  AppContainerSid: " << (appSidStr ? appSidStr : L"(null)") << L"\n";
        std::wcout << L"  UserSid: " << (userSidStr ? userSidStr : L"(null)") << L"\n";

        if (appSidStr) LocalFree(appSidStr);
        if (userSidStr) LocalFree(userSidStr);
    }


    pFree(pContainers);

    FreeLibrary(hMod);
}

int wmain(){
    ListAppSandBox();

    return 0;
}