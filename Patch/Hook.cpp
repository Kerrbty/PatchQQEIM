#include "stdafx.h"
#include "Hook.h"
#define LOWBYTE 0x000000FF


FunAddress Function[MAX_HOOK_NUM] = {0};
DWORD NowFunNum = 0;


// �ַ�����
DWORD WINAPI GetNewAddress(PVOID MyAddr)
{
	DWORD MyFunAddr = (DWORD)MyAddr;
	for (DWORD i=0; i<NowFunNum; i++)
	{
		if (Function[i].MyFunAddr == MyFunAddr)
		{
			return Function[i].NewMalloc;
		}
	}
	return NULL;
}

// hookָ���ĵ�ַ������֪����������Ĳ����������ұ����� __stdcall ���÷�ʽ��
BOOL HookProcByAddress(LPVOID ProcAddress, PVOID MyProcAddr)
{
	BYTE TMP[5] = {0};
	DWORD OldProtect;
	BYTE retbuf[] = "\x68\x00\x00\x00\x00\xC3"; // push address , retn

	
	////////////////////////////////////////////////////////////
	// ƫ�Ƶ�ַ = ���Ǻ����ĵ�ַ - ԭAPI�����ĵ�ַ - 5����������ָ��ĳ��ȣ�
	DWORD NewAddress = (DWORD)MyProcAddr - (DWORD)ProcAddress - 5; 
	
	TMP[0]=(BYTE)0xE9;
	TMP[1]=(BYTE)(NewAddress&LOWBYTE);
	TMP[2]=(BYTE)((NewAddress>>8)&LOWBYTE);
	TMP[3]=(BYTE)((NewAddress>>16)&LOWBYTE);
	TMP[4]=(BYTE)((NewAddress>>24)&LOWBYTE);

	DWORD len = 0;
	__try
	{
		while(len < 5)
		{
			DWORD i = LDE((unsigned char *)ProcAddress, 0);
			len += i;
			ProcAddress = (PVOID)((DWORD)ProcAddress + i);
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE;
	}
	
	ProcAddress = (PVOID)((DWORD)ProcAddress - len);

	*(DWORD *)(retbuf + 1) = (DWORD)ProcAddress + len;

	// ����ʹ�õĴ�С len + sizeof(retbuf) - 1
	BYTE* ProcJmp = new BYTE[len + sizeof(retbuf)]; 
	if (ProcJmp == NULL)
	{
		// �����ڴ�ʧ��
		return FALSE;
	}

	DWORD dwBytes = 0;
	// ���滻���ײ�ָ��
	if ( 
		!WriteProcessMemory(GetCurrentProcess(), ProcJmp, ProcAddress, len, &dwBytes) ||
		!WriteProcessMemory(GetCurrentProcess(), ProcJmp+len, retbuf, sizeof(retbuf), &dwBytes) 
		)
	{ 
		return FALSE;
	}
	VirtualProtect(ProcJmp, len+sizeof(retbuf), PAGE_EXECUTE_READWRITE, &OldProtect);

	// ����ԭ���������Լ�������
	DWORD i=0;
	for (i=0; i<NowFunNum; i++)
	{
		if (Function[NowFunNum].MyFunAddr == (DWORD)MyProcAddr)
		{
			// �����ǰhook���ˣ���ô����һ�����ú������Ǽ���
			Function[NowFunNum].NewMalloc = (DWORD)ProcJmp;
		}
	}
	if (i == NowFunNum)
	{
		Function[NowFunNum].MyFunAddr = (DWORD)MyProcAddr;
		Function[NowFunNum].NewMalloc = (DWORD)ProcJmp;
		NowFunNum++ ;
	}

	// �����ظ� hook��
	if (*ProcJmp == 0x0E9 )
	{
		delete []ProcJmp;
		return TRUE;
	}

	// �޸�һЩƫ��
	DWORD item_len = 0;
	DWORD new_address = (DWORD)ProcJmp;
	while(len>item_len)
	{
		if (*ProcJmp == 0x0E8 || *ProcJmp == 0x0E9 )
		{
			DWORD* OffAddr = (DWORD*)((DWORD)ProcJmp+1);
			*OffAddr = *OffAddr + ((DWORD)ProcAddress-new_address);
		}
		DWORD i = LDE((unsigned char *)ProcJmp, 0);
		item_len += i;
		ProcJmp = (PBYTE)((DWORD)ProcJmp + i);
	}

	// Inline Hook
	WriteProcessMemory(GetCurrentProcess(), ProcAddress, TMP, 5, &dwBytes);
		
	////////////////////////////////////////////////////////////
	
	return TRUE;
}

// ����hook
BOOL HookProcByName(LPCTSTR DllName, LPCSTR ProcName, PVOID MyProcAddr)
{
	
	
	HMODULE Dll = GetModuleHandle(DllName);
	if (Dll == NULL)
	{
		Dll = LoadLibrary(DllName);
	}
	if (Dll == NULL)
	{
		return FALSE;
	}
	
	PVOID ProcAddress = (PVOID)GetProcAddress(Dll, ProcName);
	if (ProcAddress == NULL)
	{
		FreeLibrary(Dll);
		return FALSE;
	}
	return HookProcByAddress(ProcAddress, MyProcAddr);
}

BOOL UnHookProcByAddress(LPVOID ProcAddress, PVOID MyProcAddr)
{
	DWORD dwBytes = 0;
	DWORD CopyAddress = GetNewAddress(MyProcAddr);
	
	if ( WriteProcessMemory(GetCurrentProcess(), ProcAddress, (LPVOID)CopyAddress, 5, &dwBytes) )
	{
		return TRUE;
	}
	return FALSE;
}


// ����unhook
BOOL UnHookProcByName(LPCTSTR DllName, LPCSTR ProcName, PVOID MyProcAddr)
{
	
	
	HMODULE Dll = GetModuleHandle(DllName);
	if (Dll == NULL)
	{
		Dll = LoadLibrary(DllName);
	}
	if (Dll == NULL)
	{
		return FALSE;
	}

	PVOID ProcAddress = (PVOID)GetProcAddress(Dll, ProcName);
	if (ProcAddress == NULL)
	{
		FreeLibrary(Dll);
		return FALSE;
	}
	return UnHookProcByAddress(ProcAddress, MyProcAddr);
}