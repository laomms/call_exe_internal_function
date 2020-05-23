
#include <stdio.h>
#include <Windows.h>
#include<stdio.h>
#include<Tlhelp32.h>
#include <iostream>
#include<stdlib.h>
#include <thread>
#include <psapi.h>

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

#define strMapName "global_share_memory"
#define SharedSize sizeof(TAgrList)
static HANDLE hMapFile;
static LPVOID lpMemFile;
static LPTSTR lpBuffer;
TAgrList AgrData;


int main()
{

    HANDLE hThread = NULL;
    void* AllocatedMemory = NULL;
    const char szExeName[] = "Client.exe";
    char szDllName[] = "MyDLL.dll";

    memset(lpMemFile, 0, SharedSize);
    AgrData.agr1 = 10;
    AgrData.agr2 = 10;
    AgrData.agr3 = 10;
    AgrData.agr4 = 10;
    AgrData.agr5 = 10;
    memcpy(lpMemFile, &AgrData, sizeof(TAgrList));

    PROCESS_INFORMATION pi;
    STARTUPINFOA si = { 0 };
    if (!CreateProcessA(szExeName, nullptr, 0, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
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

    Sleep(500);
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
    char buffer[32];
    sprintf_s(buffer, "%d", AgrData.agr3);
    MessageBoxA(NULL, buffer, "MainTitle", MB_ICONINFORMATION);

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    BOOL result = TerminateProcess(pi.hProcess, 0);
    ResumeThread(pi.hThread);
     return 0;
}
