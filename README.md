# 调用EXE的内部函数   

假设有一个client.exe，里面的有个极其复杂的算法函数，我需要在另一个可执行文件中调用这个函数并获取结果。网上有很多类似的例子，但是大部分是这个client.exe是自己写的，或者用LoadLibrary加载修复各种重定位问题。典型例子:https://bbs.pediy.com/thread-113450.htm, http://bbs.pediy.com/showthread.php?t=68730.  
但是过程都极其辛苦，特别是修复全局变量重定位问题。我这里例举的方法是通过注入dll的方式调用client.exe中的这个函数，并把函数结果传回给要调用这个函数的主程序，其中的参数传递有好多方法可以实现。典型的有socket,rpc,内存共享等，我刚开始是想利用回调函数传递参数，可是发现dll被注入后，回调根本不起作用。这里用内存共享来实现。

为了测试，我写了个简单的目标程序，这个函数只是个内部函数，并没用导出。运行该程序弹出的结果是16.  
现实中目标程序都是别人的，而且如果是windows系统程序，每个版本这个函数的rva都不一样。所以我通过搜索特征码来定位函数位置。
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
就是一个简单的加法，但是其中有用了全局变量参数计算。先找到这个函数的特征码。用IDA很容易实现:   
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
#define SharedName "Global\Injected"
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
#define SharedName "Global\Injected"
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

    char buffer[32];
    sprintf_s(buffer, "%d", result);
    MessageBoxA(NULL, buffer, "Dll Title", MB_ICONINFORMATION);   
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
```

剩下就是注入的问题，没注入一切空谈：
```c
    const char pName[] = "D:/HOOK/Debug/Client.exe";
    char LibraryName[] = "D:/HOOK/Debug/MyDLL.dll";
    
    PROCESS_INFORMATION pi;
    STARTUPINFOA si = { 0 };
      CreateProcessA(pName, nullptr, pSec, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    int LibraryNameSize = strlen(LibraryName) + 1;
    AllocatedMemory = VirtualAllocEx(pi.hProcess, NULL, LibraryNameSize, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(pi.hProcess, AllocatedMemory, LibraryName, LibraryNameSize, NULL);
    PTHREAD_START_ROUTINE ThreadRoutine = (PTHREAD_START_ROUTINE)
    GetProcAddress(GetModuleHandle(L"Kernel32"), "LoadLibraryA");
    hThread = CreateRemoteThread(pi.hProcess, NULL, 0, ThreadRoutine, AllocatedMemory, 0, NULL);
```

注入成功后，如果按照上面的代码得到结果应该是19。

