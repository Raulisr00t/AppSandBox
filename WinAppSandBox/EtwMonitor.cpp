#include "EtwMonitor.h"
#include "Logger.h"

#include <evntrace.h>
#include <evntcons.h>
#include <strsafe.h>

#pragma comment(lib, "advapi32.lib")

static TRACEHANDLE g_Session = 0;
static TRACEHANDLE g_Trace = 0;
static EVENT_TRACE_PROPERTIES* g_Props = nullptr;
static HANDLE g_Thread = nullptr;

static std::wstring g_SessionName;

static void WINAPI EventCallback(PEVENT_RECORD record)
{
    if (!record)
        return;

    USHORT id = record->EventHeader.EventDescriptor.Id;

    // Kernel Process events
    // 1 = Start, 2 = End
    if (id == 1)
    {
        Logger::Log(
            L"[ETW][PROCESS START] PID=" +
            std::to_wstring(record->EventHeader.ProcessId));
    }
    else if (id == 2)
    {
        Logger::Log(
            L"[ETW][PROCESS END] PID=" +
            std::to_wstring(record->EventHeader.ProcessId));
    }
}

static DWORD WINAPI TraceThread(LPVOID)
{
    EVENT_TRACE_LOGFILEW log{};
    log.LoggerName = &g_SessionName[0];
    log.ProcessTraceMode =
        PROCESS_TRACE_MODE_REAL_TIME |
        PROCESS_TRACE_MODE_EVENT_RECORD;
    log.EventRecordCallback = EventCallback;

    g_Trace = OpenTraceW(&log);
    if (g_Trace == INVALID_PROCESSTRACE_HANDLE)
        return 1;

    ProcessTrace(&g_Trace, 1, nullptr, nullptr);
    CloseTrace(g_Trace);
    return 0;
}

bool EtwMonitor::Start()
{
    g_SessionName =
        L"WinAppSandBoxKernel_" +
        std::to_wstring(GetCurrentProcessId());

    ULONG size =
        sizeof(EVENT_TRACE_PROPERTIES) +
        (ULONG)((g_SessionName.size() + 1) * sizeof(wchar_t));

    g_Props = (EVENT_TRACE_PROPERTIES*)
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);

    if (!g_Props)
        return false;

    g_Props->Wnode.BufferSize = size;
    g_Props->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    g_Props->Wnode.ClientContext = 1;
    g_Props->EnableFlags = EVENT_TRACE_FLAG_PROCESS;
    g_Props->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    g_Props->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

    ULONG status = StartTraceW(
        &g_Session,
        g_SessionName.c_str(),
        g_Props);

    if (status != ERROR_SUCCESS)
    {
        Logger::Log(
            L"[ETW] StartTrace failed, error=" +
            std::to_wstring(status));
        return false;
    }

    g_Thread = CreateThread(nullptr, 0, TraceThread, nullptr, 0, nullptr);

    Logger::Log(L"[ETW] Kernel process monitoring started");
    return true;
}

void EtwMonitor::Stop()
{
    if (g_Session)
    {
        ControlTraceW(
            g_Session,
            g_SessionName.c_str(),
            g_Props,
            EVENT_TRACE_CONTROL_STOP);

        Logger::Log(L"[ETW] Kernel monitoring stopped");
    }

    if (g_Thread)
        WaitForSingleObject(g_Thread, INFINITE);

    if (g_Props)
        HeapFree(GetProcessHeap(), 0, g_Props);
}
