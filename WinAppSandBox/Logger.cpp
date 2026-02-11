#pragma once 
#include "Logger.h"

static std::wofstream g_LogFile;
static std::mutex     g_LogMutex;
static bool           g_Initialized = false;

static std::wstring GetTimestamp()
{
    SYSTEMTIME st{};
    GetLocalTime(&st);

    wchar_t buffer[64];
    swprintf_s(buffer, L"%02d:%02d:%02d.%03d",
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    return buffer;
}

void Logger::Init()
{
    if (g_Initialized)
        return;

    SYSTEMTIME st{};
    GetLocalTime(&st);

    wchar_t filename[MAX_PATH];
    swprintf_s(
        filename,
        L"WinAppSandBox_%04d-%02d-%02d_%02d-%02d-%02d.log",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond);

    g_LogFile.open(filename, std::ios::out | std::ios::app);
    g_Initialized = g_LogFile.is_open();

    if (g_Initialized)
    {
        Log(L"===== SESSION STARTED =====");
    }
}

void Logger::Shutdown()
{
    if (!g_Initialized)
        return;

    Log(L"===== SESSION ENDED =====");
    g_LogFile.close();
    g_Initialized = false;
}

void Logger::Log(const std::wstring& message)
{
    if (!g_Initialized)
        return;

    std::lock_guard<std::mutex> lock(g_LogMutex);
    g_LogFile << L"[" << GetTimestamp() << L"] " << message << L"\n";
    g_LogFile.flush();
}