#include "Patch.h"
#include "Hook.h"
#include <Tlhelp32.h>
#include "BaseType.h"

#define AllocMemory(_a)  HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, _a)
#define FreeMemory(_a)   { if (_a) { HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, _a); _a=NULL; } }


// 企业QQ   TXGuiFoundation
// 私人QQ   TXGuiFoundation
typedef LRESULT (WINAPI* pSendMessage)(HWND, UINT, WPARAM, LPARAM);
typedef BOOL (WINAPI* pPostMessage)(HWND, UINT, WPARAM, LPARAM);



BOOL IsQQProcess(DWORD pid)
{
    BOOL result = FALSE; 
    HANDLE hSnapshot; 
    PROCESSENTRY32 pe = {sizeof(PROCESSENTRY32)}; 
    
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if ( hSnapshot == INVALID_HANDLE_VALUE )
    {
        OutputDebugString(TEXT("CreateToolhelp32Snapshot调用失败!\r\n"));
//        GetProcessImageFileName();
        return result;
    }
    
    if ( Process32First(hSnapshot, &pe) )
    {
        do 
        {
            if (pid == pe.th32ProcessID && memicmp(pe.szExeFile, TEXT("QQ.exe"), 6*sizeof(TCHAR)) == 0)
            {
                result = TRUE;
            }
        } while ( Process32Next(hSnapshot, &pe) );
    }
    CloseHandle(hSnapshot);

    return result;
}

/*
// LRESULT WINAPI HookSendMessageA(
//                                 HWND hWnd,      // handle to destination window
//                                 UINT Msg,       // message  
//                                 WPARAM wParam,  // first message parameter
//                                 LPARAM lParam   // second message parameter
//                                 )
// {
//     DWORD Tid, Pid = 0;
// 
//     do 
//     {
//         LPTSTR szClassName = (LPTSTR)AllocMemory(MAX_PATH*sizeof(TCHAR));
//         if (szClassName)
//         {
//             if( GetClassName(hWnd, szClassName, MAX_PATH) )
//             {
//                 if (_tcscmp(szClassName, TEXT("TXGuiFoundation")) != 0)
//                 {
//                     FreeMemory(szClassName);
//                     break;
//                 }
//             }
//             FreeMemory(szClassName);
//         }
//         
//         Tid = GetWindowThreadProcessId(hWnd, &Pid);
//         
//         if (IsQQProcess(Tid))
//         {
//             OutputDebugString(TEXT("SendMessageA 发送给QQ"));
//             return TRUE;
//         }
//     } while (0);
// 
//     pSendMessage SendMsg = (pSendMessage)GetNewAddress(HookSendMessageA);
//     if (SendMsg)
//     {
//         return SendMsg(hWnd, Msg, wParam, lParam);
//     }
//     return TRUE;
// }
// 
// LRESULT WINAPI HookSendMessageW(
//                                 HWND hWnd,      // handle to destination window
//                                 UINT Msg,       // message  
//                                 WPARAM wParam,  // first message parameter
//                                 LPARAM lParam   // second message parameter
//                                 )
// {
//     DWORD Tid, Pid = 0;
//     
//     do 
//     {
//         LPTSTR szClassName = (LPTSTR)AllocMemory(MAX_PATH*sizeof(TCHAR));
//         if (szClassName)
//         {
//             if( GetClassName(hWnd, szClassName, MAX_PATH) )
//             {
//                 if (_tcscmp(szClassName, TEXT("TXGuiFoundation")) != 0)
//                 {
//                     FreeMemory(szClassName);
//                     break;
//                 }
//             }
//             FreeMemory(szClassName);
//         }
//         
//         Tid = GetWindowThreadProcessId(hWnd, &Pid);
//         
//         if (IsQQProcess(Tid))
//         {
//             OutputDebugString(TEXT("SendMessageW 发送给QQ"));
//             return TRUE;
//         }
//     } while (0);
// 
//     pSendMessage SendMsg = (pSendMessage)GetNewAddress(HookSendMessageW);
//     if (SendMsg)
//     {
//         return SendMsg(hWnd, Msg, wParam, lParam);
//     }
//     return TRUE;
// }
// 
// 
// BOOL WINAPI HookPostMessageA(  HWND hWnd,      // handle to destination window
//                  UINT Msg,       // message  
//                  WPARAM wParam,  // first message parameter
//                  LPARAM lParam   // second message parameter
//                  )
// {
//     DWORD Tid, Pid = 0;
//     
//     do 
//     {
//         LPTSTR szClassName = (LPTSTR)AllocMemory(MAX_PATH*sizeof(TCHAR));
//         if (szClassName)
//         {
//             if( GetClassName(hWnd, szClassName, MAX_PATH) )
//             {
//                 if (_tcscmp(szClassName, TEXT("TXGuiFoundation")) != 0)
//                 {
//                     FreeMemory(szClassName);
//                     break;
//                 }
//             }
//             FreeMemory(szClassName);
//         }
//         
//         Tid = GetWindowThreadProcessId(hWnd, &Pid);
//         
//         if (IsQQProcess(Tid))
//         {
//             OutputDebugString(TEXT("PostMessageA 发送给QQ"));
//             return TRUE;
//         }
//     } while (0);
// 
//     pPostMessage PostMsg = (pPostMessage)GetNewAddress(HookPostMessageA);
//     if (PostMsg)
//     {
//         return PostMsg(hWnd, Msg, wParam, lParam);
//     }
//     return TRUE;
// }
// 
// BOOL WINAPI HookPostMessageW(  HWND hWnd,      // handle to destination window
//                              UINT Msg,       // message  
//                              WPARAM wParam,  // first message parameter
//                              LPARAM lParam   // second message parameter
//                              )
// {
//     DWORD Tid, Pid = 0;
//     
//     do 
//     {
//         LPTSTR szClassName = (LPTSTR)AllocMemory(MAX_PATH*sizeof(TCHAR));
//         if (szClassName)
//         {
//             if( GetClassName(hWnd, szClassName, MAX_PATH) )
//             {
//                 if (_tcscmp(szClassName, TEXT("TXGuiFoundation")) != 0)
//                 {
//                     FreeMemory(szClassName);
//                     break;
//                 }
//             }
//             FreeMemory(szClassName);
//         }
//         
//         Tid = GetWindowThreadProcessId(hWnd, &Pid);
//         
//         if (IsQQProcess(Tid))
//         {
//             OutputDebugString(TEXT("PostMessageW 发送给QQ"));
//             return TRUE;
//         }
//     } while (0);
//     
//     pPostMessage PostMsg = (pPostMessage)GetNewAddress(HookPostMessageW);
//     if (PostMsg)
//     {
//         return PostMsg(hWnd, Msg, wParam, lParam);
//     }
//     return TRUE;
// }
*/

typedef NTSTATUS (WINAPI *pZwOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
NTSTATUS WINAPI ZwOpenProcess(
                           PHANDLE  ProcessHandle,
                           ACCESS_MASK  DesiredAccess,
                           POBJECT_ATTRIBUTES  ObjectAttributes,
                           PCLIENT_ID  ClientId
                           )
{
    if (ClientId != NULL)
    {
        if (IsQQProcess((DWORD)ClientId->PID))
        {
            // 远程结束
            if ( PROCESS_TERMINATE&DesiredAccess )
            {
                DesiredAccess ^= PROCESS_TERMINATE;
            }
            
            // 调试结束
            if ( PROCESS_CREATE_THREAD&DesiredAccess )
            {
                DesiredAccess ^= PROCESS_CREATE_THREAD;
            }

            // 注入代码结束
            if ( PROCESS_VM_WRITE&DesiredAccess )
            {
                DesiredAccess ^= PROCESS_VM_WRITE;
            }

            // 调试结束
            if ( PROCESS_SET_INFORMATION&DesiredAccess )
            {
                DesiredAccess ^= PROCESS_SET_INFORMATION;
            }
        }
    }


    pZwOpenProcess OpenProc = (pZwOpenProcess)GetNewAddress(ZwOpenProcess);
    if (OpenProc)
    {
        return OpenProc(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
    return STATUS_SUCCESS;
}

typedef NTSTATUS (WINAPI *PQuerySystemInfo)(ULONG,PVOID,LONG,PULONG);
typedef struct 
{
    LONGLONG	UserQuadPart;
    LONGLONG	KernelQuadPart;
}HIDE_TIME, *PHIDE_TIME;

NTSTATUS WINAPI ZwQuerySystemInformation(IN ULONG SystemInformationClass,
                                         IN PVOID SystemInformation,
                                         IN LONG  SystemInformationLength,
                                         OUT PULONG ReturnLength )
{
    NTSTATUS ntStatus;
    HIDE_TIME m_Time = {0};

    PQuerySystemInfo NtQuerySystemInfo = (PQuerySystemInfo)GetNewAddress(ZwQuerySystemInformation);
    if (NtQuerySystemInfo == NULL)
    {
        return STATUS_ACCESS_DENIED;
    }
    
    ntStatus = NtQuerySystemInfo(   
        SystemInformationClass,
        SystemInformation,
        SystemInformationLength,
        ReturnLength
        );

    if (NT_SUCCESS(ntStatus))
    {
        if (SystemInformationClass == 5)
        {

            struct _SYSTEM_PROCESSES *curr = 
                (struct _SYSTEM_PROCESSES*) SystemInformation;
            struct _SYSTEM_PROCESSES *prev = NULL;
            while(curr)
            {
                if ( curr->ProcessName.Length == 12 && 
                    memicmp(curr->ProcessName.Buffer, L"QQ.exe", 12) == 0 )
                {
                    m_Time.UserQuadPart += curr->UserTime.QuadPart;
                    m_Time.KernelQuadPart += curr->KernelTime.QuadPart;
                    __try
                    {
                        if (prev)
                        {
                            if (curr->NextEntryDelta)
                                prev->NextEntryDelta += curr->NextEntryDelta;
                            else
                                prev->NextEntryDelta = 0;
                        }
                        else
                        {
                            if (curr->NextEntryDelta)
                            {
                                SystemInformation = (struct _SYSTEM_PROCESSES*)((PBYTE)SystemInformation + curr->NextEntryDelta);
                            }
                            else
                            {
                                SystemInformation = NULL;
                            }
                        }
                    }
                    __except(EXCEPTION_EXECUTE_HANDLER )
                    {
                        ;
                    }
                    
                }
                else
                {
                    // 只有不是列表中的进程时，prev才可以指向它
                    prev = curr;
                    curr->UserTime.QuadPart += m_Time.UserQuadPart;
                    curr->KernelTime.QuadPart += m_Time.KernelQuadPart;
                    m_Time.KernelQuadPart = m_Time.UserQuadPart = 0;
                }
                
                if (curr->NextEntryDelta)
                    curr = (struct _SYSTEM_PROCESSES*)((char*)curr + curr->NextEntryDelta);
                else 
                    curr = 0;
            }
        }
    }
    return ntStatus;
}

BOOL HookAll()
{
    HookProcByName("ntdll.dll", "ZwOpenProcess", ZwOpenProcess);
    HookProcByName("ntdll.dll", "ZwQuerySystemInformation", ZwQuerySystemInformation);

//     HookProcByName("user32.dll", "SendMessageA", HookSendMessageA);
//     HookProcByName("user32.dll", "SendMessageW", HookSendMessageW);
//     HookProcByName("user32.dll", "PostMessageA", HookPostMessageA);
//     HookProcByName("user32.dll", "PostMessageW", HookPostMessageW);


    return TRUE;
}


BOOL UnHookAll()
{
    UnHookProcByName("ntdll.dll", "ZwOpenProcess", ZwOpenProcess);
    UnHookProcByName("ntdll.dll", "ZwQuerySystemInformation", ZwQuerySystemInformation);

//     UnHookProcByName("user32.dll", "SendMessageA", HookSendMessageA);
//     UnHookProcByName("user32.dll", "SendMessageW", HookSendMessageW);
//     UnHookProcByName("user32.dll", "PostMessageA", HookPostMessageA);
//     UnHookProcByName("user32.dll", "PostMessageW", HookPostMessageW);

    return TRUE;
}