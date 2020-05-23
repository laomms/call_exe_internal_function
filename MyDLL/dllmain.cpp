
#include "pch.h"
#include "MyDLL.h"
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <iostream>
#include <string>
#include <atlstr.h>
#include <sstream>
using namespace std;
#pragma warning(disable:4996)

struct TAgrList
{
    int agr1 = 0;
    int agr2 = 0;
    int agr3 = 0;
    int agr4 = 0;
    int agr5 = 0;
    int agr6 = 0;
};

#define SharedSize sizeof(TAgrList)
#define strMapName "global_share_memory"


HMODULE g_hModule;
DWORD g_threadID;
static HANDLE hMapFile;
static LPVOID lpMemFile;
static LPTSTR lpBuffer;

#ifdef __cplusplus
extern "C"
{
#endif

#define DLL __declspec(dllexport)
    typedef int(__stdcall* CallBackFun)(int, int, int&);
    DLL int(__stdcall test)(int, int, int&);
    //DLL void SetCallBackFun(CallBackFun pCallBack);
    DLL void(__stdcall SetCallBackFun)(CallBackFun pCallBack);
#ifdef __cplusplus
}
#endif


CallBackFun myCallback = NULL;

DLL void __stdcall SetCallBackFun(CallBackFun pCallBack)
{
    if (pCallBack)
    {
        myCallback = pCallBack;
    }    
}

void  DoWork(int a, int b, int& c)
{
    if (myCallback)
    myCallback(a, b, c);
}

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
    BYTE BytePattern[] = "\x44\x89\x4C\x24\x00\x44\x89\x44\x24\x00\x89\x54\x24\x10\x89\x4C\x24\x08\x55\x57\x48\x81\xEC\x00\x00\x00\x00\x48\x8D\x6C\x24\x00\x48\x8B\xFC\xB9\x00\x00\x00\x00\xB8\x00\x00\x00\x00\xF3\xAB\x8B\x8C\x24\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00";
    char ByteMask[] = "xxxx?xxxx?xxxxxxxxxxxxx????xxxx?xxxx????x????xxxxx????xxx????";
    DWORD64 funcptr = FindPattern64(BytePattern, ByteMask);  
    if (funcptr == 0) 
    {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, ::GetLastError(), MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);
        MessageBoxA(nullptr, messageBuffer, "DLL: FindPattern no result!", MB_OK | MB_ICONERROR);
        LocalFree(messageBuffer);
        return FALSE;     
    }
    typedef int(__fastcall* pFunctionAddress)(int, int, int, int, int);
    pFunctionAddress pMyFunction = (pFunctionAddress)(static_cast<long long>(funcptr));
    int result = pMyFunction(AgrData.agr1, AgrData.agr2, AgrData.agr3, AgrData.agr4, AgrData.agr5);

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

int _stdcall test(int arg1, int arg2, int& argRestul)
{
    DoWork(arg1, arg2, argRestul);//取参数
    return 1;
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




