#include "stdafx.h"
#include "Hook.h"
#define LOWBYTE 0x000000FF


FunAddress Function[MAX_HOOK_NUM] = {0};
DWORD NowFunNum = 0;


// 分发函数
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

// hook指定的地址（必须知道这个函数的参数个数，且必须是 __stdcall 调用方式）
BOOL HookProcByAddress(LPVOID ProcAddress, PVOID MyProcAddr)
{
	BYTE TMP[5] = {0};
	DWORD OldProtect;
	BYTE retbuf[] = "\x68\x00\x00\x00\x00\xC3"; // push address , retn

	
	////////////////////////////////////////////////////////////
	// 偏移地址 = 我们函数的地址 - 原API函数的地址 - 5（我们这条指令的长度）
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

	// 真正使用的大小 len + sizeof(retbuf) - 1
	BYTE* ProcJmp = new BYTE[len + sizeof(retbuf)]; 
	if (ProcJmp == NULL)
	{
		// 申请内存失败
		return FALSE;
	}

	DWORD dwBytes = 0;
	// 被替换的首部指令
	if ( 
		!WriteProcessMemory(GetCurrentProcess(), ProcJmp, ProcAddress, len, &dwBytes) ||
		!WriteProcessMemory(GetCurrentProcess(), ProcJmp+len, retbuf, sizeof(retbuf), &dwBytes) 
		)
	{ 
		return FALSE;
	}
	VirtualProtect(ProcJmp, len+sizeof(retbuf), PAGE_EXECUTE_READWRITE, &OldProtect);

	// 保存原函数——自己处理函数
	DWORD i=0;
	for (i=0; i<NowFunNum; i++)
	{
		if (Function[NowFunNum].MyFunAddr == (DWORD)MyProcAddr)
		{
			// 如果以前hook过了，那么把下一步调用函数覆盖即可
			Function[NowFunNum].NewMalloc = (DWORD)ProcJmp;
		}
	}
	if (i == NowFunNum)
	{
		Function[NowFunNum].MyFunAddr = (DWORD)MyProcAddr;
		Function[NowFunNum].NewMalloc = (DWORD)ProcJmp;
		NowFunNum++ ;
	}

	// 不能重复 hook啊
	if (*ProcJmp == 0x0E9 )
	{
		delete []ProcJmp;
		return TRUE;
	}

	// 修改一些偏移
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

// 进行hook
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


// 进行unhook
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