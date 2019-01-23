#include "Patch.h"
#include <windows.h>


BOOL WINAPI   DllMain( HINSTANCE hModule, DWORD dwReason, LPVOID lpvReserved )
{
    switch(dwReason)
    {
        case DLL_PROCESS_DETACH:
            UnHookAll();
            break;
        case DLL_PROCESS_ATTACH:
            HookAll();
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}



INT Patch()
{
    OutputDebugString(TEXT("Debug View Information!\r\n"));
    return 0;
}