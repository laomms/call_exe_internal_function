
#include <stdio.h>
#include <Windows.h>
#include <cstring>
#include <string>
#ifdef  UNICODE
typedef const wchar_t* LPCTSTR;
#else
typedef const char* LPCTSTR;
#endif

LPCSTR lpTexts = "Message from client!";
LPCSTR lpCaptions = "Client Title";
//int c = 6;
int f = 10;

int __stdcall myFunc(int a, int b) {
    int d = 0 + a + b+10;   
    return d;
}

int __fastcall myFastFunc(int a, int b, int c, int d,int e) {
    int g = a + b + c + d+e+f+10;
    return g;
}

void myfunction(const char* input)
{
    printf(input);
}

int main()
{  
    int d = myFastFunc(0, 0,0,0,0);
    char buffer[32];
    sprintf_s(buffer, "%d", d);
    MessageBoxA(NULL, buffer, lpCaptions, MB_ICONINFORMATION);
    return 0;
}


