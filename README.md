# 调用EXE的内部函数   

假设有一个client.exe，里面的有个极其复杂的算法函数，我需要在另一个可执行文件中调用这个函数并获取结果。网上有很多类似的例子，但是大部分是这个client.exe是自己写的，或者用LoadLibrary加载修复各种重定位问题。典型例子:https://bbs.pediy.com/thread-113450.htm, http://bbs.pediy.com/showthread.php?t=68730.  
但是过程都极其辛苦，特别是修复全局变量重定位问题。我这里例举的方法是通过注入dll的方式调用client.exe中的这个函数，并把函数结果传回给要调用这个函数的主程序，其中的参数传递有好多方法可以实现。典型的有socket,rpc,内存共享等，我刚开始是想利用回调函数传递参数，可是发现dll被注入后，回调根本不起作用。这里用内存共享来实现。

为了测试，我写了个简单的目标程序，这个函数只是个内部函数，并没用导出。现实中目标程序都是别人的，而且如果是windows系统程序，每个版本这个函数的rva都不一样。所以我通过搜索特征码来定位函数位置。
```c
int c = 6;
int __stdcall myFunc(int a, int b) {
    int d = c + a + b+10;
    char buffer[32];
    sprintf_s(buffer, "%d",d);
    MessageBoxA(NULL, buffer, lpCaptions, MB_ICONINFORMATION);
    return d;
}
```
就是一个简单的加法，但是其中有用了全局变量参数计算。先找到这个函数的特征码。用IDA很容易实现:   
![image](https://github.com/laomms/call_exe_internal_function/blob/master/01.png)   

首先写要注入的dll，先把这个查找函数地址的实现：
```c
  char ProcessName[] = "Client.exe";
    MODULEINFO modinfo = { 0 };
    HMODULE hModule = GetModuleHandleA(ProcessName);
    if (hModule == 0)
        return 0;        
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
