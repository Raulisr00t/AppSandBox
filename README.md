# 🧱 AppSandBox

AppSandBox is a lightweight Windows console utility that enumerates all **AppContainer sandboxes** (used by Windows Store, UWP, and sandboxed applications).  
It retrieves and displays detailed information such as container name, display name, SID, description, working directory, and associated package details.

---

## 🚀 Features

- Lists all registered AppContainers on your Windows system  
- Displays detailed metadata for each sandbox:
  - AppContainer Name  
  - Display Name  
  - Description  
  - Working Directory  
  - Package Full Name  
  - AppContainer SID and User SID  
- Uses **NetworkIsolation APIs** from `FirewallAPI.dll`  
- Works on Windows 8, 10, 11 and later

---

## 🧩 How It Works

The tool uses the following Windows API calls:
- `NetworkIsolationEnumAppContainers` — enumerates sandboxed app containers
- `NetworkIsolationFreeAppContainers` — frees the allocated memory
- `ConvertSidToStringSid` — converts security identifiers to readable strings

The utility dynamically loads these functions from **FirewallAPI.dll**, ensuring compatibility even if the header isn’t directly included.

---

## 🛠️ Build Instructions

### Prerequisites
- **Windows 10 or later**
- **Visual Studio 2019+** or **MSVC Build Tools**
- C++17 or higher
- Administrator privileges (recommended)

### Steps
1. Clone the repository:
   ```powershell
   git clone https://github.com/Raulisr00t/AppSandBox.git
   cd AppSandBox```
   
2. Open the project in Visual Studio.

3. Build the project (x64 or x86).

4. Run from a command prompt:
  ```powershell
  AppSandBox.exe
  ```
## 📄 Example Output
```powershell
Found 5 AppContainers:
--------------------------------------------
Container 1:
  AppContainerName: Microsoft.WindowsCalculator_8wekyb3d8bbwe!App
  DisplayName: Calculator
  Description: Perform calculations quickly
  WorkingDirectory: C:\Program Files\WindowsApps\Microsoft.WindowsCalculator_...
  PackageFullName: Microsoft.WindowsCalculator_10.2203.8.0_x64__8wekyb3d8bbwe
  AppContainerSid: S-1-15-2-xxxxxxx
  UserSid: S-1-5-21-xxxxxxx
--------------------------------------------
Container 2:
  ...
```
## ⚠️ Notes

Requires Windows with AppContainer support.

Some entries may have (null) fields if information isn’t available.

Run from an elevated prompt for best results.
