#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <Winternl.h>
#include <stdint.h>
#include <tchar.h>
#define FILE_PATH "C:\\Users\\Sh3lldor\\Run_Process.exe"
#define SUCCESS 0
#define FAIL 1
DWORD rva_to_va(DWORD rva, PIMAGE_NT_HEADERS p_nt_header, LPVOID lp_file_base);
typedef struct LDR_DATA_ENTRY {
	LIST_ENTRY		InMemoryOrderModuleList;
	PVOID			BaseAddress;
	PVOID			EntryPoint;
	ULONG			SizeOfImage;
	UNICODE_STRING 	FullDllName;
	UNICODE_STRING 	BaseDllName;
	ULONG			Flags;
	SHORT			LoadCount;
	SHORT			TlsIndex;
	LIST_ENTRY		HashTableEntry;
	ULONG			TimeDateStamp;
} LDR_DATA_ENTRY, *PLDR_DATA_ENTRY;


__declspec(naked) PLDR_DATA_ENTRY get_peb() {
	__asm {
		mov eax, fs:[0x30]
		mov eax, [eax + 0x0C]
		mov eax, [eax + 0x1C]
		retn
	}
}

int main() {
	PLDR_DATA_ENTRY peb = get_peb();
	
	HANDLE hFile = CreateFile(_T(FILE_PATH), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		_tprintf_s(TEXT("Could not open file"));
		return SUCCESS;
	}

	HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

	if (hFileMapping == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hFile);
		_tprintf_s(TEXT("Could not create file mapping"));
		return SUCCESS;
	}

	LPVOID lpFileBase = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);

	if (lpFileBase == NULL)
	{
		CloseHandle(hFile);
		_tprintf_s(TEXT("Could not create map view of file"));
		return SUCCESS;
	}

	PIMAGE_DOS_HEADER p_dos_header = (PIMAGE_DOS_HEADER)lpFileBase;

	PIMAGE_NT_HEADERS p_nt_header = (PIMAGE_NT_HEADERS)((DWORD)p_dos_header + (DWORD)p_dos_header->e_lfanew);


	// dll or exe
	if ((p_nt_header->FileHeader.Characteristics & IMAGE_FILE_DLL)) {
		printf("dll file.\n");
	}
	else if ((p_nt_header->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)) {
		printf("executable file.\n");
	}

	//get sections
	PIMAGE_SECTION_HEADER p_section_header = (PIMAGE_SECTION_HEADER)(p_nt_header + 1);
	for (int i = 0;i < p_nt_header->FileHeader.NumberOfSections; ++i) {
		printf("section name --> %s\n", p_section_header->Name);
		++p_section_header;
	}

	//get checksum
	printf("check sum from optional header --> %x\n", p_nt_header->OptionalHeader.CheckSum);

	int number_of_functions = 0;

	DWORD rva = (DWORD)p_nt_header->OptionalHeader.DataDirectory[0].VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY p_export_dir = (PIMAGE_EXPORT_DIRECTORY)(rva_to_va(rva, p_nt_header, lpFileBase));
	if (p_export_dir == NULL) {
		fprintf(stderr, "va is null");
		getchar();
		return FAIL;
	}
	DWORD* address_of_functions = (DWORD*)rva_to_va(p_export_dir->AddressOfNames, p_nt_header, lpFileBase);
	if (address_of_functions == NULL) {
		fprintf(stderr, "va is null");
		getchar();
		return FAIL;
	}
	for (unsigned int i = 1; i < p_export_dir->NumberOfNames;++i) {
		char* func_name = (char*)rva_to_va(address_of_functions[i], p_nt_header, lpFileBase);
		if (func_name == NULL) {
			fprintf(stderr, "va is null");
			getchar();
			return FAIL;
		}
		printf("%s\n", func_name);
		++number_of_functions;
	}
	printf("%d", number_of_functions);

	//list all dll names and their address from the current pe
	while (peb->BaseAddress) {
		fprintf(stdout, "%S loaded to address %p\n", peb->BaseDllName.Buffer, peb->BaseAddress);
		// SEARCHING FOR kernel32.dll
		if (!wcscmp(peb->BaseDllName.Buffer,L"KERNEL32.DLL")) {
			// Need to complete
		}
		peb = (PLDR_DATA_ENTRY)peb->InMemoryOrderModuleList.Flink;
	}


	getchar();
	return SUCCESS;
}
/*
DWORD rva_to_va(DWORD rva, PIMAGE_NT_HEADERS p_nt_header, LPVOID lp_file_base) {
	DWORD va = NULL;
	PIMAGE_SECTION_HEADER p_section_header = p_nt_header + 1;
	for (int i = 0;i < p_nt_header->FileHeader.NumberOfSections;++i) {
		DWORD section_virtual_address = p_section_header->VirtualAddress;
		if (section_virtual_address < rva && rva < p_section_header->VirtualAddress + p_section_header->Misc.VirtualSize) {
			DWORD offset_from_section = rva - section_virtual_address;
			DWORD offset_from_file_begining = p_section_header->PointerToRawData + offset_from_section;
			va = (PBYTE)lp_file_base + offset_from_file_begining;
			break;
		}
		p_section_header++;
	}

	return va;
}
*/
