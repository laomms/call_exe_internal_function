# 调用EXE的内部函数   

假设有一个client.exe，里面的有个极其复杂的算法函数，我需要在另一个可执行文件中调用这个函数并获取结果。网上有很多类似的例子，但是大部分是这个client.exe是自己写的，或者用LoadLibrary加载修复各种重定位问题。典型例子:https://bbs.pediy.com/thread-113450.htm, http://bbs.pediy.com/showthread.php?t=68730.  
但是过程都极其辛苦，特别是修复全局变量重定位问题。我这里例举的方法是通过注入dll的方式调用client.exe中的这个函数，并把函数结果传回给要调用这个函数的主程序，其中的参数传递有好多方法可以实现。典型的有socket,rpc,内存共享等，我刚开始是想利用回调函数传递参数，可是发现dll被注入后，回调根本不起作用。这里用内存共享来实现。

为了测试，我写了个简单的目标程序，这个函数只是个内部函数，并没用导出。就是一个简单的加法，但是其中有用了全局变量参数计算。运行该程序弹出的结果是6+0+0+10=16.  

```c
int c = 6;
int __stdcall myFunc(int a, int b) {
    int d = c + a + b+10;
    char buffer[32];
    sprintf_s(buffer, "%d",d);
    MessageBoxA(NULL, buffer, lpCaptions, MB_ICONINFORMATION);
    return d;
}

int main()
{  
    myFunc(0, 0);
    return 0;
}
```
![image](https://github.com/laomms/call_exe_internal_function/blob/master/00.png)   
现实中目标程序都是别人的，而且如果是windows系统程序，每个版本这个函数的rva都不一样。所以我通过搜索特征码来定位函数位置。
先找到这个函数的特征码。用IDA插件sigmaker很容易实现:   
![image](https://github.com/laomms/call_exe_internal_function/blob/master/01.png)   

首先写要注入的dll，先把这个查找函数地址的实现：
```c
    char ProcessName[] = "Client.exe";
    char BytePattern[] = "\x55\x8B\xEC\x81\xEC\x00\x00\x00\x00\x53\x56\x57\x8D\xBD\x00\x00\x00\x00\xB9\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xF3\xAB\xA1\x00\x00\x00\x00\x33\xC5\x89\x45\xFC\xB9\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xA1\x00\x00\x00\x00\x03\x45\x08";
    char ByteMask[] = "xxxxx????xxxxx????x????x????xxx????xxxxxx????x????x????xxx";
    DWORD funcptr = FindPattern(ProcessName, BytePattern, ByteMask);
    if (funcptr == 0) 
    {
        MessageBoxA(NULL, "FindPattern no result!", "Dll Title", MB_ICONINFORMATION);
        return FALSE;
    }
```
```c
MODULEINFO GetModuleInfo(char* szModule)
{
    MODULEINFO modinfo = { 0 };
    HMODULE hModule = GetModuleHandleA(szModule);
    if (hModule == 0)
        return modinfo;
    GetModuleInformation(GetCurrentProcess(), hModule, &modinfo, sizeof(MODULEINFO));
    return modinfo;
}

DWORD FindPattern(char* module, char* pattern, char* mask)
{
    MODULEINFO mInfo = GetModuleInfo(module);
    DWORD base = (DWORD)mInfo.lpBaseOfDll;
    DWORD size = (DWORD)mInfo.SizeOfImage;

    DWORD patternLength = (DWORD)strlen(mask);

    for (DWORD i = 0; i < size - patternLength; i++)
    {
        bool found = true;
        for (DWORD j = 0; j < patternLength; j++)
        {
            found &= mask[j] == '?' || pattern[j] == *(char*)(base + i + j);
        }

        if (found)
        {
            return base + i;
        }
    }

    return NULL;
}
```
函数指针funcptr已经找到了，调用就简单了。这是个标准的函数，就两个参数。
```c
    typedef int(__stdcall* pFunctionAddress)(int a, int b);
    pFunctionAddress pMyFunction = (pFunctionAddress)(funcptr);
    int result = pMyFunction(AgrData.agr1, AgrData.agr2);
```
由于没有解决重定位的问题把这个指针传回给主程序也没用，主程序中不能直接调用这个函数，但是注入DLL后，DLL中是可以任意调用这个函数，但是这两个参数必须从主程序获取，而且得到计算结果后还得送回给主程序。这样就变相的实现主程序调用了这个函数。剩下来就利用内存共享实现传递参数。先在主程序定义一个结构用于传递参数，把这个结构写入内存后共享给DLL，DLL读取内存后把参数取出去调用这个函数计算结果，得到结果后重新写入内存，再由主程序读取这个结构获取计算结果：
```c
struct TAgrList
{
    DWORD agr1 = 0;
    DWORD agr2 = 0;
    DWORD agr3 = 0;
};
#define SharedSize sizeof(TAgrList)
#define SharedName "global_share_memory"
```
```c
  TAgrList AgrData;
    hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SharedSize, SharedName);
    if (hMapFile == nullptr) {
        MessageBoxA(nullptr, "Failed to create file mapping!", "DLL_PROCESS_ATTACH", MB_OK | MB_ICONERROR);
        return FALSE;
    }


    lpMemFile = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (lpMemFile == nullptr) {
        MessageBoxA(nullptr, "Failed to map shared memory!", "DLL_PROCESS_ATTACH", MB_OK | MB_ICONERROR);
        return FALSE;
    }

    memset(lpMemFile, 0, SharedSize);
    AgrData.agr1 = 1;
    AgrData.agr2 = 2;
    AgrData.agr3 = 0;
    memcpy(lpMemFile, &AgrData, sizeof(TAgrList));

```
这里我们把参数1和参数2设置好，写入共享内存供dll读取，这个是主程序要参数计算的两个参数。
dll方用于读取的代码，注意共享名和和数据结构：
```c
struct TAgrList
{
    DWORD agr1 = 0;
    DWORD agr2 = 0;
    DWORD agr3 = 0;
};
#define SharedSize sizeof(TAgrList)
#define SharedName "global_share_memory"
```
```c
    TAgrList AgrData; 
    HANDLE hMapFile = OpenFileMappingA(FILE_MAP_READ, FALSE, SharedName);
    if (!hMapFile)
    {
        MessageBoxA(nullptr, "Failed to open file mapping!", "DLL_PROCESS_ATTACH", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    lpBuffer = (LPTSTR)MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, SharedSize);
    if (lpBuffer == NULL)
    {
        MessageBoxA(nullptr, "Failed to map shared memory!", "DLL_PROCESS_ATTACH", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    CopyMemory(&AgrData, lpBuffer, SharedSize);
```
dll读取共享内存并用这两个参数参与函数计算结构，然后把结果写入共享内存：
```c
    int result = pMyFunction(AgrData.agr1, AgrData.agr2);    
    hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, SharedSize, SharedName);
    if (hMapFile == nullptr) {
        MessageBoxA(nullptr, "Failed to create file mapping!", "DLL_PROCESS_ATTACH", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    lpMemFile = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (lpMemFile == nullptr) {
        MessageBoxA(nullptr, "Failed to map shared memory!", "DLL_PROCESS_ATTACH", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    memset(lpMemFile, 0, SharedSize);
    AgrData.agr3 = result;
    memcpy(lpMemFile, &AgrData, sizeof(TAgrList));
```

主程序读取共享出来的结果：
```c
    Sleep(200);
    HANDLE hMapFile = OpenFileMappingA(FILE_MAP_READ, FALSE, SharedName);
    if (!hMapFile)
    {
        MessageBoxA(nullptr, "Failed to open file mapping!", "DLL_PROCESS_ATTACH", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    lpBuffer = (LPTSTR)MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, SharedSize);
    if (lpBuffer == NULL)
    {
        MessageBoxA(nullptr, "Failed to map shared memory!", "DLL_PROCESS_ATTACH", MB_OK | MB_ICONERROR);
        return FALSE;
    }
    CopyMemory(&AgrData, lpBuffer, SharedSize);
    //测试下结果
    char buffer[32];
    sprintf_s(buffer, "%d", AgrData.agr3);
    MessageBoxA(NULL, buffer, "MainTitle", MB_ICONINFORMATION);
```
主程序要先映射参数到内存，然后注入，再在内存中读出结果。
所以中间必须有个注入过程，没注入一切空谈：
```c
    const char pName[] = "D:/HOOK/Debug/Client.exe";
    char LibraryName[] = "D:/HOOK/Debug/MyDLL.dll";
    
    PROCESS_INFORMATION pi;
    STARTUPINFOA si = { 0 };
    CreateProcessA(pName, nullptr, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    int LibraryNameSize = strlen(LibraryName) + 1;
    AllocatedMemory = VirtualAllocEx(pi.hProcess, NULL, LibraryNameSize, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(pi.hProcess, AllocatedMemory, LibraryName, LibraryNameSize, NULL);
    PTHREAD_START_ROUTINE ThreadRoutine = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"Kernel32"), "LoadLibraryA");    
    hThread = CreateRemoteThread(pi.hProcess, NULL, 0, ThreadRoutine, AllocatedMemory, 0, NULL);
```

一切就绪后，运行主程序，如果按照上面的代码得到结果应该是6+1+2+10=19。   
![image](https://github.com/laomms/call_exe_internal_function/blob/master/02.png)   

如果要设置共享的内存安全等级，只要添加：
```c
if (!InitializeSecurityDescriptor(&SecDesc, SECURITY_DESCRIPTOR_REVISION))
        throw std::runtime_error("InitializeSecurityDescriptor error");
    if (!SetSecurityDescriptorDacl(&SecDesc, true, NULL, false))
        throw std::runtime_error("SetSecurityDescriptorDacl error");

    SecAttr.nLength = sizeof(SecAttr);
    SecAttr.lpSecurityDescriptor = &SecDesc;
    SecAttr.bInheritHandle = TRUE;
    pSec = &SecAttr;
```
然后创建进程是第三个参数调用这个安全属性：
```c
hMapFile = CreateFileMapping(INVALID_HANDLE_VALUE, pSec, PAGE_READWRITE, NULL, SharedSize, SharedName);
CreateProcessA(pName, nullptr, pSec, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)
```
有些系统进程注入需要主程序提升权限才能注入：
```c
BOOL EnablePrivilege(BOOL enable)
{
    // 得到令牌句柄
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_READ, &hToken))
        return FALSE;

    // 得到特权值
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
        return FALSE;

    // 提升令牌句柄权限
    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL))
        return FALSE;

    // 关闭令牌句柄
    CloseHandle(hToken);
    return TRUE;
}
```
在int main()先EnablePrivilege(TRUE)然后开始注入工作。

64位下实现代码差不多，就是改下那个FindPattern，下面是全部源码，dll:
```c

#include "pch.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
using namespace std;
#pragma warning(disable:4996)

struct TAgrList
{
    int agr1 = 0;
    int agr2 = 0;
    int agr3 = 0;
};

#define SharedSize sizeof(TAgrList)
#define strMapName "global_share_memory"
typedef int(__cdecl* pFunctionAddress)(int , int );

HMODULE g_hModule;
DWORD g_threadID;
static HANDLE hMapFile;
static LPVOID lpMemFile;
static LPTSTR lpBuffer;



BOOL Compare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
    for (; *szMask; ++szMask, ++pData, ++bMask)
    {
        if (*szMask == 'x' && *pData != *bMask)
            return 0;
    }
    return (*szMask) == NULL;
}

DWORD64 FindPattern64(BYTE* bMask, char* szMask)
{
    MODULEINFO moduleInfo = { 0 };
    GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &moduleInfo, sizeof(MODULEINFO));

    DWORD64 dwBaseAddress = (DWORD64)moduleInfo.lpBaseOfDll;
    DWORD64 dwModuleSize = (DWORD64)moduleInfo.SizeOfImage;

    for (DWORD64 i = 0; i < dwModuleSize; i++)
    {
        if (Compare((BYTE*)(dwBaseAddress + i), bMask, szMask))
            return (DWORD64)(dwBaseAddress + i);
    }

    return 0;
}


DWORD WINAPI MyThread(LPVOID)
{
    TAgrList AgrData; 
    HANDLE hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, strMapName);
    if (!hMapFile)
    {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "DLL: Failed to open file mapping!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;
    }
    lpBuffer = (LPTSTR)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, SharedSize);
    if (!lpBuffer )
    {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "DLL: Failed to map shared memory!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;      
    }
    CopyMemory(&AgrData, (char*)lpBuffer, SharedSize);
    char ProcessName[] = "Client.exe";
    MODULEINFO modinfo = { 0 };
    HMODULE hModule = GetModuleHandleA(ProcessName);
    if (hModule == 0)
        return 0;        
    BYTE BytePattern[] = "\x89\x54\x24\x10\x89\x4C\x24\x08\x55\x57\x48\x81\xEC\x00\x00\x00\x00\x48\x8D\x6C\x24\x00\x48\x8B\xFC\xB9\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xF3\xAB\x8B\x8C\x24\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00";
    char ByteMask[] = "xxxxxxxxxxxxx????xxxx?xxxx????x????xxxxx????xxx????";
    DWORD64 funcptr = FindPattern64(BytePattern, ByteMask);  
    if (funcptr == 0) 
    {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "DLL: FindPattern no result!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;     
    }
   
    pFunctionAddress pMyFunction = (pFunctionAddress)(static_cast<long long>(funcptr));
    int result = pMyFunction(AgrData.agr1, AgrData.agr2);

    hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, SharedSize, strMapName);
    if (hMapFile == nullptr) {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "DLL: Failed to create file mapping!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;
    }
    lpMemFile = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (lpMemFile == nullptr) {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "DLL: Failed to map shared memory!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;      
    }

    memset(lpMemFile, 0, SharedSize);
    AgrData.agr3 = result;
    memcpy(lpMemFile, &AgrData, sizeof(TAgrList));
    return 0;
}


BOOL APIENTRY DllMain(HMODULE hModule, DWORD  fdwReason, LPVOID lpReserved)
{    
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        //MessageBoxA(NULL, "注入成功!", "Dll Title", MB_OK);
        DisableThreadLibraryCalls(hModule);
        CreateThread(NULL, NULL, &MyThread, NULL, NULL, &g_threadID);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        UnmapViewOfFile(lpMemFile);
        CloseHandle(hMapFile);
        break;
    }
    return TRUE;
}
```
主程序：
```c

#include <stdio.h>
#include <Windows.h>
#include<stdio.h>
#include<Tlhelp32.h>
#include <iostream>
#include<stdlib.h>
#include <thread>

using namespace std;

struct TAgrList
{
    int agr1 = 0;
    int agr2 = 0;
    int agr3 = 0;
};

#define strMapName "global_share_memory"
#define SharedSize sizeof(TAgrList)
static HANDLE hMapFile;
static LPVOID lpMemFile;
static LPTSTR lpBuffer;



BOOL EnablePrivilege(BOOL enable)
{
    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_READ, &hToken))
        return FALSE;

    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
        return FALSE;

    TOKEN_PRIVILEGES tp = {};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL))
        return FALSE;
    CloseHandle(hToken);
    return TRUE;
}

int main()
{
    EnablePrivilege(TRUE);   
    HANDLE hThread = NULL;
    void* AllocatedMemory = NULL;
    const char szExeName[] = "D:/HOOK/x64/Debug/Client.exe";
    char szDllName[] = "D:/HOOK/x64/Debug/MyDLL.dll";

    SECURITY_ATTRIBUTES SecAttr, * pSec = nullptr;
    SECURITY_DESCRIPTOR SecDesc;
    if (!InitializeSecurityDescriptor(&SecDesc, SECURITY_DESCRIPTOR_REVISION))
        throw std::runtime_error("InitializeSecurityDescriptor error");
    if (!SetSecurityDescriptorDacl(&SecDesc, true, NULL, false))
        throw std::runtime_error("SetSecurityDescriptorDacl error");

    SecAttr.nLength = sizeof(SecAttr);
    SecAttr.lpSecurityDescriptor = &SecDesc;
    SecAttr.bInheritHandle = TRUE;
    pSec = &SecAttr;



    TAgrList AgrData;
    hMapFile = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,NULL, SharedSize, strMapName);
    if (hMapFile == nullptr) {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "Failed to create file mapping!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;
    }


    lpMemFile = MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    if (lpMemFile == nullptr) {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "Failed to map shared memory!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;      
    }

    memset(lpMemFile, 0, SharedSize);
    AgrData.agr1 = 1;
    AgrData.agr2 = 2;
    AgrData.agr3 = 0;
    memcpy(lpMemFile, &AgrData, sizeof(TAgrList));

    PROCESS_INFORMATION pi;
    STARTUPINFOA si = { 0 };
    if (!CreateProcessA(szExeName, nullptr, pSec, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "Failed to CreateProcess!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;
    }

    int LibraryNameSize = strlen(szDllName) + 1;
    AllocatedMemory = VirtualAllocEx(pi.hProcess, NULL, LibraryNameSize, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(pi.hProcess, AllocatedMemory, szDllName, LibraryNameSize, NULL);
    PTHREAD_START_ROUTINE ThreadRoutine = (PTHREAD_START_ROUTINE) GetProcAddress(GetModuleHandleA("Kernel32"), "LoadLibraryA");
    hThread = CreateRemoteThread(pi.hProcess, NULL, 0, ThreadRoutine, AllocatedMemory, 0, NULL);
    WaitForSingleObject(hThread, INFINITE);
    Sleep(200);
    HANDLE hMapFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, strMapName);
    if (!hMapFile)
    {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "Failed to open file mapping!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;
    }
    lpBuffer = (LPTSTR)MapViewOfFile(hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, SharedSize);
    if (lpBuffer == NULL)
    {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "Failed to MapViewOfFile!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;      
    }
    CopyMemory(&AgrData, lpBuffer, SharedSize);
    //测试下结果
    char buffer[32];
    sprintf_s(buffer, "%d", AgrData.agr3);
    MessageBoxA(NULL, buffer, "MainTitle", MB_ICONINFORMATION);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    BOOL result = TerminateProcess(pi.hProcess, 0);
    //ResumeThread(pi.hThread);
     return 0;
}

```
