#pragma once
#include <windows.h>
#include <chrono>
#include <mutex>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <string>

#pragma once
#include <string>

class Logger
{
public:
    // Call once at program start
    static void Init();

    // Call once before exit
    static void Shutdown();

    // Log a line (safe to call anywhere)
    static void Log(const std::wstring& message);
};
