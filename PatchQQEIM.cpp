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

// �ض�λ��ṹ
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


// ���ӵ����
BOOL ImportDll(LPTSTR PeFileName, char* dllName, char* funName)
{
	// �ȱ���һ��
	size_t len = _tcslen(PeFileName);
	LPTSTR bakfile = (LPTSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (len+4)*sizeof(TCHAR));
	_tcscpy(bakfile, PeFileName);
	int i;
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("����:"));
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

	// ��ȡpe��������
	HANDLE handle = CreateFile(PeFileName, 
		GENERIC_READ|GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	if (handle == INVALID_HANDLE_VALUE)
	{
		SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("����Ӧ��ʧ�� ..."));
		return FALSE;
	}

	DWORD dwBytes = 0;
	DWORD dwsize = GetFileSize(handle, NULL);
	PBYTE buf = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwsize*sizeof(BYTE));
	ReadFile(handle, buf, dwsize, &dwBytes, NULL);

	// ����
	PIMAGE_DOS_HEADER Header = (PIMAGE_DOS_HEADER)buf;
	PIMAGE_NT_HEADERS peheader = 
		(PIMAGE_NT_HEADERS)((LPBYTE)Header + Header->e_lfanew);
	

	// ��һ������
	IMAGE_SECTION_HEADER new_section = {0};
	strcpy((char*)new_section.Name, ".Patch");
	
	PIMAGE_SECTION_HEADER SectionHeader = (PIMAGE_SECTION_HEADER)( (DWORD)peheader + 
											sizeof(peheader->FileHeader) + 
											sizeof(peheader->Signature) +
											peheader->FileHeader.SizeOfOptionalHeader ); // �ڱ���Ŀ�ʼ

	// IAT��ַ
	DWORD VirtualAddress = peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	
	new_section.SizeOfRawData = peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size + strlen(dllName) + strlen(funName) + 14;
	new_section.SizeOfRawData += sizeof(IMAGE_IMPORT_DESCRIPTOR); // �ļ���С
	new_section.Misc.VirtualSize = (new_section.SizeOfRawData/peheader->OptionalHeader.SectionAlignment + 1 )*peheader->OptionalHeader.SectionAlignment; // �ڴ��С
	new_section.Characteristics = IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE|IMAGE_SCN_CNT_INITIALIZED_DATA;

	// ö���������ε�ַ
	for (i=0; i<peheader->FileHeader.NumberOfSections; i++)
	{
		DWORD ulsize = SectionHeader[i].Misc.VirtualSize;
		if ( ulsize > SectionHeader[i].SizeOfRawData )
		{
			ulsize = SectionHeader[i].SizeOfRawData;
		}

		// �ҵ�������ļ�ƫ��
		if (VirtualAddress >= SectionHeader[i].VirtualAddress && 
			VirtualAddress <= SectionHeader[i].VirtualAddress+SectionHeader[i].Misc.VirtualSize)
		{
			VirtualAddress = VirtualAddress- SectionHeader[i].VirtualAddress + SectionHeader[i].PointerToRawData;
		}
		
		// �������һ�����κ���
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

	SetFilePointer(handle, 0, NULL, FILE_BEGIN); // �����ļ�β��
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

	// �޸�Image��С
	DWORD dwIDEI = peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if (dwIDEI%peheader->OptionalHeader.SectionAlignment)
	{
		dwIDEI = dwIDEI/peheader->OptionalHeader.SectionAlignment + 1;
	}
	else
	{
		dwIDEI = dwIDEI/peheader->OptionalHeader.SectionAlignment;
	}
	peheader->OptionalHeader.SizeOfImage += peheader->OptionalHeader.SectionAlignment * dwIDEI; // Image ��С���

	// ������ַ�޸�
	peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = new_section.VirtualAddress+strlen(dllName)+3+strlen(funName)+1+8;
	peheader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size += sizeof(IMAGE_IMPORT_DESCRIPTOR);

	// ���μ�1
	peheader->FileHeader.NumberOfSections++;

	SetFilePointer(handle, 0, NULL, FILE_BEGIN);
	WriteFile(handle, buf, peheader->OptionalHeader.FileAlignment, &dwBytes, NULL);
	HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, buf);
	CloseHandle(handle);
	return TRUE;
}

// ��Ȩ
BOOL EnableDebugPrivilege(BOOL bEnable) 
{ 
	
	BOOL fOK = FALSE;
	HANDLE hToken;
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) //�򿪽��̷�������
	{ 
		//��ͼ�޸ġ����ԡ���Ȩ
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


// �����ҵQQ�Ƿ��������У��ر��Ժ��ٴ򲹶�
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
			if (MessageBox(NULL, TEXT("��⵽��ҵQQ��������, �Ƿ���������� ?"), TEXT("��ʾ"), MB_YESNO) == IDYES)
			{
				HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, procEntry.th32ProcessID);
				if (handle == NULL)
				{
					SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("Ȩ�޲���"));
					retval = FALSE;
					break;
				}
				TerminateProcess(handle, 0);
				CloseHandle(handle);
				wsprintf(tmp, "���� %s �ɹ�\n", procEntry.szExeFile);
				SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)tmp);
                Sleep(500);
			}
			else
			{
				SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("�û�ȡ������"));
				retval = FALSE;
				break;
			}
			
		}
		else if (memicmp(procEntry.szExeFile, TEXT("QQEIMPlatform.exe"), 17*sizeof(TCHAR)) == 0)
		{
			HANDLE handle = OpenProcess(PROCESS_TERMINATE, FALSE, procEntry.th32ProcessID);
			if (handle == NULL)
			{
				SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("Ȩ�޲���"));
				retval = FALSE;
				break;
			}
			TerminateProcess(handle, 0);
			CloseHandle(handle);
			wsprintf(tmp, "���� %s �ɹ�\n", procEntry.szExeFile);
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

// ����Դ����Ϊ�ļ�
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
		SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("д��Patch.dll���� ...\n") );
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
                        LPVOID StartAddress /* ��ʼ���ҵĵ�ַ */ , 
                        DWORD VirtualAddSize /* ��������buf��С */ , 
                        LPVOID FindedBuf /* �������� */ ,
                        DWORD BufSize /* ���ݴ�С */ )
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

// �����򲹶�
BOOL Patch(PTSTR path)
{
	LPTSTR PatchFile = new TCHAR[MAX_PATH+20];

    Sleep(500);

	// д�벹���ļ�
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("д�벹�� ..."));
	wsprintf(PatchFile, TEXT("%s\\Patch.dll"), path);
	if( !SaveResFile(PatchFile, TEXT("BINARY"), (char*)1721) )
	{
		delete []PatchFile;
		return FALSE;
	}

	// ������ҵQQ��������QQ
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("д��zlib.dll ..."));
	wsprintf(PatchFile, TEXT("%s\\zlib.dll"), path);
	if( !ImportDll(PatchFile, "Patch.dll", "Patch") )
	{
		delete []PatchFile;
		return FALSE;
	}

    // ��ҵQQ���񲹶�
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("д��QQEIMPlatform.exe ..."));
	wsprintf(PatchFile, TEXT("%s\\QQEIMPlatform.exe"), path);
	if( !ImportDll(PatchFile, "Patch.dll", "Patch") )
	{
		delete []PatchFile;
		return FALSE;
	}

    // ɾ�����Ѳ���
    // ��������UNICODE�ַ���: DelContactPromptDlg\DelContactPromptDlg.xml|DelContactPromptDlg
    SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("ɾ������MainFrame.dll���� ..."));
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
            SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("MainFrame.dll�����ɹ�!"));
        }
        else
        {
            SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("MainFrame.dll����ʧ�ܣ��޷�����!"));
        }
        HeapFree(GetProcessHeap(), HEAP_NO_SERIALIZE, bBuf);
        CloseHandle(handle);
    }
    else
    {
        SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("��MainFrame.dllʧ�ܣ��޷�Ӧ�ò���!"));
    }

    // ���ֻ����ʾ��ҵQQ�����ܵĴ���
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("QQEIMTips.exe����"));
	Sleep(500);
	LPTSTR newfile = new TCHAR[MAX_PATH+20];
	wsprintf(PatchFile, TEXT("%s\\QQEIMTips.exe"), path);
	wsprintf(newfile, TEXT("%s\\QQEIMTips.exe.bak"), path);
	MoveFile(PatchFile, newfile);
	CopyFile(PatchFile, newfile, FALSE);
	DeleteFile(PatchFile);

	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("����Ӧ�����!!!"));
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
	
	// ��ȡ��װĿ¼
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
		Patch(path); // ����
	}
	else
	{
		// û��ע��������ҵ���װĿ¼�����ڱ�Ŀ¼����
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
// ��ԭ�������ָ��򲹶�ǰ�ĳ���
//////////////////////////////////////////////////////////////////////////
void DisPatch(TCHAR* path)
{
	LPTSTR PatchFile = new TCHAR[MAX_PATH+20];
	LPTSTR newfile = new TCHAR[MAX_PATH+20];
	
	// ����
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("д��zlib.dll ..."));
	wsprintf(PatchFile, TEXT("%s\\zlib.dll"), path);
	wsprintf(newfile, TEXT("%s\\zlib.bak"), path);
	CopyFile(newfile, PatchFile, FALSE);
	
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("д��QQEIMPlatform.exe ..."));
	wsprintf(PatchFile, TEXT("%s\\QQEIMPlatform.exe"), path);
	wsprintf(newfile, TEXT("%s\\QQEIMPlatform.bak"), path);
	CopyFile(newfile, PatchFile, FALSE);
	
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("QQEIMTips.exe.bak����"));
	wsprintf(PatchFile, TEXT("%s\\QQEIMTips.exe"), path);
	wsprintf(newfile, TEXT("%s\\QQEIMTips.exe.bak"), path);
	CopyFile(newfile, PatchFile, FALSE);
	
	SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)TEXT("�����ָ����!!!"));
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
	
	// ��ȡ��װĿ¼
	// HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Tencent\QQEIM
	if( GetInstallPath(path, MAX_PATH) )
	{
		_tcscat(path, TEXT("\\Bin"));
		SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)path);
		DisPatch(path);
	}
	else
	{
		// û��ע��������ҵ���װĿ¼�����ڱ�Ŀ¼����
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
// ���ڹ���
//////////////////////////////////////////////////////////////////////////

void move_Middle(HWND hWnd)
{
	RECT rect;
	int x,y;
	GetWindowRect(hWnd, &rect);//�õ���ǰ���ڴ�С��Ϣ
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
		//�û��Զ�����Ϣ
		switch(wParam) 
		{
		case IDC_PATCH:
			{
				g_list_hwnd = GetDlgItem(hWnd, IDC_LISTINFO);
				SendMessage(g_list_hwnd, LB_RESETCONTENT, 0, 0);
				SendMessage(g_list_hwnd, LB_ADDSTRING, 0, (LPARAM)"��ʼӦ�ò���...");
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
	//��ʾ����
	DialogBoxParam(hInstance,(LPCSTR)IDD_DIALOG1 ,NULL, (DLGPROC)ProcWinMain, NULL);
	return TRUE;
}