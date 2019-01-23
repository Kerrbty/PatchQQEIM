#include <windows.h>
#include <ShellAPI.h>
#include "resource.h"
#include <tchar.h>
#include <Tlhelp32.h>
#include <Shlwapi.h>
#pragma comment(lib, "Shlwapi.lib")

BOOL ImportDll(LPTSTR PeFileName, char* dllName, char* funName);
BOOL EnableDebugPrivilege(BOOL bEnable) ;
BOOL CanPatch();
BOOL GetInstallPath(LPTSTR path, DWORD lenth);

// 重定位表结构
typedef struct _OffTable{
	USHORT addr:12;
	USHORT flags:4;
}OffTable, *pOffTable;

typedef struct _RELOADTABLE{
	DWORD StartVirtualAddress;
	DWORD size;
	OffTable Table[1];
}RELOADTABLE, *pRELOADTABLE;

HWND g_list_hwnd = NULL;


// 增加导入表
BOOL ImportDll(LPTSTR PeFileName, char* dllName, char* funName)
{
	// 先备份一个
	size_t len = _tcslen(PeFileName);
	LPTSTR bakfile = (LPTSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (len+4)*sizeof(TCHAR));
	_tcscpy(bakfile, PeFileName);
	int i;
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("备份:"));
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)PeFileName);
	for (i=4; ; i--)
	{
		if ( *(bakfile+len-i) == TEXT('.') || i == 0)
		{
			_tcscpy(bakfile+len-i, (".bak"));
			break;
		}
	}
	CopyFile(PeFileName, bakfile, TRUE);
	HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, bakfile);

	// 读取pe所有数据
	HANDLE handle = CreateFile(PeFileName, 
		GENERIC_READ|GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (handle == INVALID_HANDLE_VALUE)
	{
		SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("补丁应用失败 ..."));
		return FALSE;
	}

	DWORD dwBytes = 0;
	DWORD dwsize = GetFileSize(handle, NULL);
	PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwsize*sizeof(BYTE));
	ReadFile(handle, buf, dwsize, &dwBytes, NULL);

	// 解析
	PIMAGE_DOS_HEADER Header = (PIMAGE_DOS_HEADER)buf;
	PIMAGE_NT_HEADERS peheader = 
		(PIMAGE_NT_HEADERS)((LPBYTE)Header + Header->e_lfanew);
	

	// 加一个区段
	IMAGE_SECTION_HEADER new_section = {0};
	strcpy((char*)new_section.Name, ".Patch");
	
	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)( (DWORD)peheader + 
											sizeof(peheader->FileHeader) + 
											sizeof(peheader->Signature) +
											peheader->FileHeader.SizeOfOptionalHeader ); // 节表项的开始

	// IAT地址
	DWORD VirtualAddress = peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	
	new_section.SizeOfRawData = peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size + strlen(dllName) + strlen(funName) + 14;
	new_section.SizeOfRawData += sizeof(IMAGE_IMPORT_DESCRIPTOR); // 文件大小
	new_section.Misc.VirtualSize = (new_section.SizeOfRawData/peheader->OptionalHeader.SectionAlignment + 1 )*peheader->OptionalHeader.SectionAlignment; // 内存大小
	new_section.Characteristics = IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_CNT_INITIALIZED_DATA;

	// 枚举现有区段地址
	for (i=0; i<peheader->FileHeader.NumberOfSections; i++)
	{
		DWORD ulsize = SectionHeader[i].Misc.VirtualSize;
		if ( ulsize > SectionHeader[i].SizeOfRawData )
		{
			ulsize = SectionHeader[i].SizeOfRawData;
		}

		// 找到导入表文件偏移
		if (VirtualAddress >= SectionHeader[i].VirtualAddress && 
			VirtualAddress <= SectionHeader[i].VirtualAddress+SectionHeader[i].Misc.VirtualSize)
		{
			VirtualAddress = VirtualAddress- SectionHeader[i].VirtualAddress + SectionHeader[i].PointerToRawData;
		}
		
		// 加在最后一个区段后面
		if (new_section.VirtualAddress <= SectionHeader[i].VirtualAddress)
		{
			DWORD temp = ulsize%peheader->OptionalHeader.SectionAlignment? (ulsize/peheader->OptionalHeader.SectionAlignment+1)*peheader->OptionalHeader.SectionAlignment: ulsize;
			new_section.VirtualAddress = SectionHeader[i].VirtualAddress + temp;
		}
		if (new_section.PointerToRawData <= SectionHeader[i].PointerToRawData )
		{
			DWORD temp = SectionHeader[i].SizeOfRawData%peheader->OptionalHeader.FileAlignment?
						(SectionHeader[i].SizeOfRawData/peheader->OptionalHeader.FileAlignment+1)*peheader->OptionalHeader.FileAlignment: 
						SectionHeader[i].SizeOfRawData;
			new_section.PointerToRawData = SectionHeader[i].PointerToRawData + temp;
				
		}
	}

	new_section.SizeOfRawData = peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size+sizeof(IMAGE_IMPORT_DESCRIPTOR)+strlen(dllName)+3+strlen(funName)+1+8;
	memcpy(&SectionHeader[peheader->FileHeader.NumberOfSections], &new_section, sizeof(new_section));

	SetFilePointer(handle, 0, NULL, FILE_BEGIN); // 设置文件尾部
	WriteFile(handle, buf, dwsize, &dwBytes, NULL);
	SetFilePointer(handle, new_section.PointerToRawData, NULL, FILE_BEGIN);
	WriteFile(handle, dllName, strlen(dllName)+1, &dwBytes, NULL);
	WriteFile(handle, "\0\0\0", 2, &dwBytes, NULL);
	WriteFile(handle, funName, strlen(funName)+1, &dwBytes, NULL);
	DWORD FileStart = new_section.VirtualAddress+strlen(dllName)+1;
	WriteFile(handle, &FileStart, 4, &dwBytes, NULL);
	WriteFile(handle, "\0\0\0\0", 4, &dwBytes, NULL);
	WriteFile(handle, buf+VirtualAddress, peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size-sizeof(IMAGE_IMPORT_DESCRIPTOR), &dwBytes, NULL);

	FileStart = new_section.VirtualAddress+strlen(dllName)+3+strlen(funName)+1;
	WriteFile(handle, &FileStart, 4, &dwBytes, NULL);
	WriteFile(handle, "\0\0\0\0\0\0\0\0", 8, &dwBytes, NULL);
	WriteFile(handle, &new_section.VirtualAddress, 4, &dwBytes, NULL);
	WriteFile(handle, &FileStart, 4, &dwBytes, NULL);
	WriteFile(handle, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 0x14, &dwBytes, NULL);

	// 修改Image大小
	DWORD dwIDEI = peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if (dwIDEI%peheader->OptionalHeader.SectionAlignment)
	{
		dwIDEI = dwIDEI/peheader->OptionalHeader.SectionAlignment + 1;
	}
	else
	{
		dwIDEI = dwIDEI/peheader->OptionalHeader.SectionAlignment;
	}
	peheader->OptionalHeader.SizeOfImage += peheader->OptionalHeader.SectionAlignment * dwIDEI; // Image 大小变大

	// 输入表地址修改
	peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = new_section.VirtualAddress+strlen(dllName)+3+strlen(funName)+1+8;
	peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);

	// 区段加1
	peheader->FileHeader.NumberOfSections++;

	SetFilePointer(handle, 0, NULL, FILE_BEGIN);
	WriteFile(handle, buf, peheader->OptionalHeader.FileAlignment, &dwBytes, NULL);
	HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, buf);
	CloseHandle(handle);
	return TRUE;
}

// 提权
BOOL EnableDebugPrivilege(BOOL bEnable) 
{ 
	
	BOOL fOK = FALSE;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) //打开进程访问令牌
	{ 
		//试图修改“调试”特权
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount = 1;
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
		tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
		AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		fOK = (GetLastError() == ERROR_SUCCESS);
		CloseHandle(hToken); 
	} 
	return fOK; 
}


// 检测企业QQ是否正在运行，关闭以后再打补丁
BOOL CanPatch()
{
	BOOL retval = TRUE;
	EnableDebugPrivilege(TRUE);
	HANDLE procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); 
	if(procSnap == INVALID_HANDLE_VALUE) 
	{ 
		return TRUE; 
	} 

	LPTSTR tmp = new TCHAR[MAX_PATH];
	PROCESSENTRY32 procEntry = { 0 }; 
	procEntry.dwSize = sizeof(PROCESSENTRY32); 
	BOOL bRet = Process32First(procSnap, &procEntry); 
	while(bRet) 
	{ 
		if (memicmp(procEntry.szExeFile, TEXT("QQEIM.exe"), 9*sizeof(TCHAR)) == 0)
		{
			if (MessageBox(NULL, TEXT("检测到企业QQ正在运行, 是否结束并继续 ?"), TEXT("提示"), MB_YESNO) == IDYES)
			{
				HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, procEntry.th32ProcessID);
				if (handle == NULL)
				{
					SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("权限不够"));
					retval = FALSE;
					break;
				}
				TerminateProcess(handle, 0);
				CloseHandle(handle);
				wsprintf(tmp, "结束 %s 成功\n", procEntry.szExeFile);
				SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)tmp);
                Sleep(500);
			}
			else
			{
				SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("用户取消操作"));
				retval = FALSE;
				break;
			}
			
		}
		else if (memicmp(procEntry.szExeFile, TEXT("QQEIMPlatform.exe"), 17*sizeof(TCHAR)) == 0)
		{
			HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, procEntry.th32ProcessID);
			if (handle == NULL)
			{
				SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("权限不够"));
				retval = FALSE;
				break;
			}
			TerminateProcess(handle, 0);
			CloseHandle(handle);
			wsprintf(tmp, "结束 %s 成功\n", procEntry.szExeFile);
			SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)tmp);
            Sleep(500);
		}
		bRet = Process32Next(procSnap, &procEntry);
	} 
	CloseHandle(procSnap);
	delete []tmp;

	return retval;
}

BOOL GetInstallPath(LPTSTR path, DWORD lenth)
{
	// HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Tencent\QQEIM
	HKEY hKey;
	BOOL retval = FALSE;
	
	if ( RegOpenKey(HKEY_LOCAL_MACHINE, TEXT("SOFTWARE\\Tencent\\QQEIM"), &hKey) == ERROR_SUCCESS )
	{
		DWORD Type = 0;
		if ( RegQueryValueEx(hKey, TEXT("Install"), NULL, &Type, (PBYTE)path, &lenth) == ERROR_SUCCESS )
		{
			retval = TRUE;
		}
		RegCloseKey(hKey);
	}
	return retval;
}

// 将资源保存为文件
BOOL SaveResFile(PTSTR szSaveFileName, PTSTR szResName, PTSTR ResId)
{
	HMODULE module = GetModuleHandle(NULL);
	HRSRC res = FindResource( module, ResId, szResName);
	HGLOBAL hglob = LoadResource(module, res);
	DWORD dwsize = SizeofResource(module, res);
	if (res == NULL)
	{
#ifdef _DEBUG
		DWORD error = GetLastError();
#endif
		return FALSE;
	}
	LPVOID pres = LockResource(hglob);
	
	HANDLE hpfile = CreateFile(szSaveFileName, 
								GENERIC_WRITE,
								0,
								NULL,
								CREATE_ALWAYS,
								FILE_ATTRIBUTE_NORMAL,
								NULL);
	if (hpfile == INVALID_HANDLE_VALUE)
	{
#ifdef _DEBUG
		DWORD error = GetLastError();
		SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("写入Patch.dll错误 ...\n") );
#endif
		return FALSE;
	}
	DWORD dwBytes = 0;
	WriteFile(hpfile, pres, dwsize, &dwBytes, NULL);
	
	CloseHandle(hpfile);
	UnlockResource(hglob);
	return TRUE;
}


LPVOID FromAddFindValue(
                        LPVOID StartAddress /* 开始查找的地址 */ , 
                        DWORD VirtualAddSize /* 查找数据buf大小 */ , 
                        LPVOID FindedBuf /* 查找数据 */ ,
                        DWORD BufSize /* 数据大小 */ )
{
    DWORD i = 0;
    for ( i=0; i<=VirtualAddSize-BufSize; i++)
    {
        if ( memcmp((LPBYTE)StartAddress+i, FindedBuf, BufSize) == NULL )
        {
            return (LPBYTE)StartAddress+i;
        }
    }
    return NULL;
}

// 真正打补丁
BOOL Patch(PTSTR path)
{
	LPTSTR PatchFile = new TCHAR[MAX_PATH+20];

    Sleep(500);

	// 写入补丁文件
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("写入补丁 ..."));
	wsprintf(PatchFile, TEXT("%s\\Patch.dll"), path);
	if( !SaveResFile(PatchFile, TEXT("BINARY"), (char*)1721) )
	{
		delete []PatchFile;
		return FALSE;
	}

	// 补丁企业QQ主程序检测QQ
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("写入zlib.dll ..."));
	wsprintf(PatchFile, TEXT("%s\\zlib.dll"), path);
	if( !ImportDll(PatchFile, "Patch.dll", "Patch") )
	{
		delete []PatchFile;
		return FALSE;
	}

    // 企业QQ服务补丁
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("写入QQEIMPlatform.exe ..."));
	wsprintf(PatchFile, TEXT("%s\\QQEIMPlatform.exe"), path);
	if( !ImportDll(PatchFile, "Patch.dll", "Patch") )
	{
		delete []PatchFile;
		return FALSE;
	}

    // 删除好友补丁
    // 搜索代码UNICODE字符串: DelContactPromptDlg\DelContactPromptDlg.xml|DelContactPromptDlg
    SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("删除好友MainFrame.dll补丁 ..."));
    wsprintf(PatchFile, TEXT("%s\\MainFrame.dll"), path);
    HANDLE handle = CreateFile(PatchFile, GENERIC_READ|GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (handle != INVALID_HANDLE_VALUE)
    {
        DWORD dwBytes;
        DWORD dwSize = GetFileSize(handle, NULL);
        PBYTE bBuf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);
        SetFilePointer(handle, 0, NULL, FILE_BEGIN);
        ReadFile(handle, bBuf, dwSize, &dwBytes, NULL);

        LPBYTE pathcaddr = (LPBYTE)FromAddFindValue(bBuf, dwBytes, "\x33\xDB\xC1\xE8\x02\x43\x23\xC3\x0F", 9);
        if (pathcaddr != NULL && pathcaddr[-5] == 0xE8)
        {
            memcpy(pathcaddr+8, "\x90\xE9", 2);
            SetFilePointer(handle, 0, NULL, FILE_BEGIN);
            WriteFile(handle, bBuf, dwBytes, &dwBytes, NULL);
            SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("MainFrame.dll补丁成功!"));
        }
        else
        {
            SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("MainFrame.dll搜索失败，无法补丁!"));
        }
        HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, bBuf);
        CloseHandle(handle);
    }
    else
    {
        SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("打开MainFrame.dll失败，无法应用补丁!"));
    }

    // 这个只是提示企业QQ管理功能的窗口
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("QQEIMTips.exe改名"));
	Sleep(500);
	LPTSTR newfile = new TCHAR[MAX_PATH+20];
	wsprintf(PatchFile, TEXT("%s\\QQEIMTips.exe"), path);
	wsprintf(newfile, TEXT("%s\\QQEIMTips.exe.bak"), path);
	MoveFile(PatchFile, newfile);
	CopyFile(PatchFile, newfile, FALSE);
	DeleteFile(PatchFile);

	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("补丁应用完成!!!"));
	delete []PatchFile;
	delete []newfile;
	return TRUE;
}


int DoSomeThing()
{
	if( !CanPatch() )
	{
 		return EXIT_FAILURE;
    }
	
	LPTSTR path = new TCHAR[MAX_PATH];
	ZeroMemory(path, MAX_PATH*sizeof(TCHAR));
	
	// 获取安装目录
	// HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Tencent\QQEIM
	if( GetInstallPath(path, MAX_PATH) )
	{
        size_t ilen = _tcslen(path);
        if (ilen >0 && path[ilen-1] == '\\')
        {
            path[ilen-1] = '\x0';
        }
		_tcscat(path, TEXT("\\Bin"));
		SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)path);
		Patch(path); // 补丁
	}
	else
	{
		// 没在注册表里面找到安装目录，则在本目录中找
		if( PathFileExists("QQEIM.exe") )
		{
			GetCurrentDirectory(MAX_PATH, path);
			SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)path);
			Patch(path);
		}
		else
		{
			SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)"Can't find 'QQEIM.exe'");
		}
	}
	delete []path;
	return -1;
}





//////////////////////////////////////////////////////////////////////////
// 还原补丁，恢复打补丁前的程序
//////////////////////////////////////////////////////////////////////////
void DisPatch(TCHAR* path)
{
	LPTSTR PatchFile = new TCHAR[MAX_PATH+20];
	LPTSTR newfile = new TCHAR[MAX_PATH+20];
	
	// 补丁
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("写入zlib.dll ..."));
	wsprintf(PatchFile, TEXT("%s\\zlib.dll"), path);
	wsprintf(newfile, TEXT("%s\\zlib.bak"), path);
	CopyFile(newfile, PatchFile, FALSE);
	
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("写入QQEIMPlatform.exe ..."));
	wsprintf(PatchFile, TEXT("%s\\QQEIMPlatform.exe"), path);
	wsprintf(newfile, TEXT("%s\\QQEIMPlatform.bak"), path);
	CopyFile(newfile, PatchFile, FALSE);
	
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("QQEIMTips.exe.bak改名"));
	wsprintf(PatchFile, TEXT("%s\\QQEIMTips.exe"), path);
	wsprintf(newfile, TEXT("%s\\QQEIMTips.exe.bak"), path);
	CopyFile(newfile, PatchFile, FALSE);
	
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("补丁恢复完成!!!"));
	delete []PatchFile;
	delete []newfile;
	return;
}

void backpatch()
{
	if( !CanPatch() )
	{
		return;
	}
	
	LPTSTR path = new TCHAR[MAX_PATH];
	ZeroMemory(path, MAX_PATH*sizeof(TCHAR));
	
	// 获取安装目录
	// HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Tencent\QQEIM
	if( GetInstallPath(path, MAX_PATH) )
	{
		_tcscat(path, TEXT("\\Bin"));
		SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)path);
		DisPatch(path);
	}
	else
	{
		// 没在注册表里面找到安装目录，则在本目录中找
		if( PathFileExists("QQEIM.exe") )
		{
			GetCurrentDirectory(MAX_PATH, path);
			SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)path);
			DisPatch(path);
		}
		else
		{
			SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)"Can't find 'QQEIM.exe'");
		}
	}
	delete []path;
}










//////////////////////////////////////////////////////////////////////////
// 窗口过程
//////////////////////////////////////////////////////////////////////////

void move_Middle(HWND hWnd)
{
	RECT rect;
	int x,y;
	GetWindowRect(hWnd, &rect);//得到当前窗口大小信息
	x = rect.right - rect.left;
	y = rect.bottom - rect.top;
	MoveWindow(hWnd, (GetSystemMetrics(SM_CXSCREEN)- x)>>1, (GetSystemMetrics(SM_CYSCREEN)-y)>>1, x, y , TRUE);
}

INT_PTR CALLBACK ProcWinMain(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	switch(Msg)
	{
	case WM_INITDIALOG:
		move_Middle(hWnd);
		break;

	case WM_SHOWWINDOW:
		move_Middle(hWnd);
		break;

	case WM_COMMAND:
		//用户自定义消息
		switch(wParam) 
		{
		case IDC_PATCH:
			{
				g_list_hwnd = GetDlgItem(hWnd, IDC_LISTINFO);
				SendMessage(g_list_hwnd, LB_RESETCONTENT, 0, 0);
				SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)"开始应用补丁...");
				DoSomeThing();
			}
			break;
		case IDC_REPA:
			{
				g_list_hwnd = GetDlgItem(hWnd, IDC_LISTINFO);
				backpatch();
			}
			break;

		case IDC_EXIT:
			PostMessage(hWnd, WM_CLOSE, NULL, NULL);
			break;
		case IDOK:
		case IDCANCEL:
			PostMessage(hWnd, WM_CLOSE, NULL, NULL);
			break;
		}  
		break;

	case WM_CLOSE:
		EndDialog(hWnd, 0);
		break;

	default:
		return FALSE;
		break;
	}
	return 0;
} 

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	//显示窗口
	DialogBoxParam(hInstance,(LPCSTR)IDD_DIALOG1 ,NULL, (DLGPROC)ProcWinMain, NULL);
	return TRUE;
}