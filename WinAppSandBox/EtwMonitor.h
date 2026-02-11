#pragma once
#include <windows.h>

class EtwMonitor
{
public:
    // Start ETW monitoring
    static bool Start();

    // Stop ETW monitoring
    static void Stop();
};
