#include <windows.h>
#include <winternl.h>
#include "shellcode.h"

#pragma comment(linker, "/Entry:EntryMain")

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

struct KERNEL32
{
	PVOID BaseAddr;
	WinAPIPtr WinExec;
	WinAPIPtr ExitProcess;
	LOADLIBRARYA LoadLibraryA;
};

struct USER32
{
	HMODULE BaseAddr;
	WinAPIPtr MessageBoxA;
};
//#pragma data_seg(".text")
DWORD user[] = { 0x72657375, 0x642e3233, 0x00006c6c };
DWORD sz_String[] = { 0x214e5750, 0x00000000 };
BYTE pMessage[] = { 'M','e','s','s','a','g','e','B','o','x','A' };
HMODULE GetProcAddrByHash(PVOID LibBaseAddr, DWORD FnHash);
//HMODULE GetProcAddressWithHash(DWORD dwModuleFunctionHash);
HMODULE GetKernel32Base();
DWORD HashKey(char* key);

int EntryMain() {
	struct USER32 user32;
	struct KERNEL32 kernel32;
	kernel32.BaseAddr = GetKernel32Base();
	kernel32.LoadLibraryA = GetProcAddrByHash(kernel32.BaseAddr, HASH_LoadLibraryA);
	kernel32.ExitProcess = GetProcAddrByHash(kernel32.BaseAddr, HASH_ExitProcess);
	user32.BaseAddr = kernel32.LoadLibraryA(user);
	user32.MessageBoxA = GetProcAddrByHash(user32.BaseAddr, HASH_MessageBoxA);
	user32.MessageBoxA(0, sz_String, 0, MB_OK);
	kernel32.ExitProcess();
	
	


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
/*
HMODULE GetProcAddressWithHash(DWORD dwModuleFunctionHash)
{
	PPEB PebAddress;
	PMY_PEB_LDR_DATA pLdr;
	PMY_LDR_DATA_TABLE_ENTRY pDataTableEntry;
	PVOID pModuleBase;
	PIMAGE_NT_HEADERS pNTHeader;
	DWORD dwExportDirRVA;
	PIMAGE_EXPORT_DIRECTORY pExportDir;
	PLIST_ENTRY pNextModule;
	DWORD dwNumFunctions;
	USHORT usOrdinalTableIndex;
	PDWORD pdwFunctionNameBase;
	PCSTR pFunctionName;
	UNICODE_STRING BaseDllName;
	DWORD dwModuleHash;
	DWORD dwFunctionHash;
	PCSTR pTempChar;
	DWORD i;

#if defined(_WIN64)
	PebAddress = (PPEB)__readgsqword(0x60);
#else
	PebAddress = (PPEB)__readfsdword(0x30);
#endif

	pLdr = (PMY_PEB_LDR_DATA)PebAddress->Ldr;
	pNextModule = pLdr->InLoadOrderModuleList.Flink;
	pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pNextModule;

	while (pDataTableEntry->DllBase != NULL)
	{
		dwModuleHash = 0;
		pModuleBase = pDataTableEntry->DllBase;
		BaseDllName = pDataTableEntry->BaseDllName;
		pNTHeader = (PIMAGE_NT_HEADERS)((ULONG_PTR)pModuleBase + ((PIMAGE_DOS_HEADER)pModuleBase)->e_lfanew);
		dwExportDirRVA = pNTHeader->OptionalHeader.DataDirectory[0].VirtualAddress;

		// Get the next loaded module entry
		pDataTableEntry = (PMY_LDR_DATA_TABLE_ENTRY)pDataTableEntry->InLoadOrderLinks.Flink;

		// If the current module does not export any functions, move on to the next module.
		if (dwExportDirRVA == 0)
		{
			continue;
		}

		// Calculate the module hash
		for (i = 0; i < BaseDllName.MaximumLength; i++)
		{
			pTempChar = ((PCSTR)BaseDllName.Buffer + i);

			dwModuleHash = ROTR32(dwModuleHash, 13);

			if (*pTempChar >= 0x61)
			{
				dwModuleHash += *pTempChar - 0x20;
			}
			else
			{
				dwModuleHash += *pTempChar;
			}
		}

		pExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)pModuleBase + dwExportDirRVA);

		dwNumFunctions = pExportDir->NumberOfNames;
		pdwFunctionNameBase = (PDWORD)((PCHAR)pModuleBase + pExportDir->AddressOfNames);

		for (i = 0; i < dwNumFunctions; i++)
		{
			dwFunctionHash = 0;
			pFunctionName = (PCSTR)(*pdwFunctionNameBase + (ULONG_PTR)pModuleBase);
			pdwFunctionNameBase++;

			pTempChar = pFunctionName;

			do
			{
				dwFunctionHash = ROTR32(dwFunctionHash, 13);
				dwFunctionHash += *pTempChar;
				pTempChar++;
			} while (*(pTempChar - 1) != 0);

			dwFunctionHash += dwModuleHash;

			if (dwFunctionHash == dwModuleFunctionHash)
			{
				usOrdinalTableIndex = *(PUSHORT)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfNameOrdinals) + (2 * i));
				return (HMODULE)((ULONG_PTR)pModuleBase + *(PDWORD)(((ULONG_PTR)pModuleBase + pExportDir->AddressOfFunctions) + (4 * usOrdinalTableIndex)));
			}
		}
	}

	// All modules have been exhausted and the function was not found.
	return NULL;
}

*/
