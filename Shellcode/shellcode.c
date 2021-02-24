#include <windows.h>
#include <winternl.h>
#include "shellcode.h"

#pragma comment(linker, "/Entry:EntryMain")

#define ROTR32(value, shift)	(((DWORD) value >> (BYTE) shift) | ((DWORD) value << (32 - (BYTE) shift)))
#define LOADLIBRARYA_HASH				0x0726774c
#define MESSAGEBOXA_HASH				0x07568345
#define GETPROCADDRESS_HASH				0x7802f749

typedef ULONG_PTR(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef NTSTATUS(WINAPI* LDRLOADDLL)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);
typedef int (WINAPI* MESSAGEBOXA)(HWND, LPSTR, LPSTR, UINT);

BYTE puser[] = { 'u','s','e','r','3','2','.','d','l','l' };
BYTE pMessage[] = { 'M','e','s','s','a','g','e','B','o','x','A' };
HMODULE GetProcAddressWithHash(DWORD dwModuleFunctionHash);

int EntryMain() {
	
	LOADLIBRARYA pLoadLibraryA = NULL;
	GETPROCADDRESS pGetProcAddress = NULL;
	pLoadLibraryA = GetProcAddressWithHash(LOADLIBRARYA_HASH);
	if (pLoadLibraryA == NULL)
		return -1;

	HMODULE puser32dll = pLoadLibraryA(puser); //TODO:fix data address 
	pGetProcAddress = GetProcAddressWithHash(GETPROCADDRESS_HASH);
	if (pGetProcAddress == NULL)
		return -1;

	MESSAGEBOXA pMessageBox = pGetProcAddress(puser32dll, pMessage); //TODO:fix data address 
	pMessageBox(NULL, NULL, NULL, NULL);
	return 0;
}





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


