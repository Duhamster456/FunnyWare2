#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <string.h>
#include <stdlib.h>

bool MatchDllName(const UNICODE_STRING* fullDllName, LPCSTR lpModuleName) {
    if (fullDllName->Length == 0 || lpModuleName[0] == '\0') return false;
    char moduleUpper[256] = { 0 };
    size_t len = strlen(lpModuleName);
    for (size_t i = 0; i < len && i < 255; i++) {
        moduleUpper[i] = (char)toupper(lpModuleName[i]);
    }

    size_t asciiLen = strlen(moduleUpper);
    PWCHAR wptr = fullDllName->Buffer;
    size_t wlen = fullDllName->Length / sizeof(WCHAR);
    size_t matchLen = 0;
    size_t wstart = wlen;

    while (wstart > 0 && matchLen < asciiLen) {
        wstart--;
        if (towupper(wptr[wstart]) == (WCHAR)moduleUpper[asciiLen - 1 - matchLen]) {
            matchLen++;
        }
        else {
            matchLen = 0;
        }
    }

    return (matchLen == asciiLen);
}


inline PPEB GetCurrentPEB() {
#ifdef _M_X64
    return (PPEB)__readgsqword(0x60); // Read 64-bit value at GS:0x60
#elif _M_IX86
    return (PPEB)__readfsdword(0x30);
#endif
}

void printAllDlls() {
    PPEB peb = GetCurrentPEB();
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY head = &(ldr->InMemoryOrderModuleList);
    PLIST_ENTRY curr = head->Flink;
    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(reinterpret_cast<BYTE*>(curr) - 16);
        UNICODE_STRING dll_name = entry->FullDllName;
        std::wcout << dll_name.Buffer << std::endl;
        curr = curr->Flink;
    }
}

HMODULE GetModuleHandle2(LPCSTR lpModuleName) {
    PPEB peb = GetCurrentPEB();
    PPEB_LDR_DATA ldr = peb->Ldr;
    PLIST_ENTRY head = &(ldr->InMemoryOrderModuleList);
    PLIST_ENTRY curr = head->Flink;
    while (curr != head) {
        PLDR_DATA_TABLE_ENTRY entry = reinterpret_cast<PLDR_DATA_TABLE_ENTRY>(reinterpret_cast<BYTE*>(curr) - 16);
        UNICODE_STRING dll_name = entry->FullDllName;
        if (MatchDllName(&dll_name, lpModuleName)) {
            return reinterpret_cast<HMODULE>(entry->DllBase);
        }
        curr = curr->Flink;
    }
    return 0;
}

void* GetProcAddress2(HMODULE hModule, LPCSTR lpProcName) {
    IMAGE_DOS_HEADER* library_msdos = reinterpret_cast<IMAGE_DOS_HEADER*>(hModule);
    BYTE* library_base = reinterpret_cast<BYTE*>(hModule);
    PIMAGE_NT_HEADERS64 library_pe = reinterpret_cast<PIMAGE_NT_HEADERS64>(library_base + library_msdos->e_lfanew);
    PIMAGE_OPTIONAL_HEADER64 library_optional = &(library_pe->OptionalHeader);
    PIMAGE_DATA_DIRECTORY export_dirent = library_optional->DataDirectory;
    DWORD export_rva = export_dirent->VirtualAddress;
    DWORD export_size = export_dirent->Size;
    PIMAGE_EXPORT_DIRECTORY export_dir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(library_base + export_rva);
    DWORD name_rva = export_dir->Name;
    DWORD* func_names_array = reinterpret_cast<DWORD*>(library_base + export_dir->AddressOfNames);
    WORD* ordinals_array = reinterpret_cast<WORD*>(library_base + export_dir->AddressOfNameOrdinals);
    DWORD* func_addresses_array = reinterpret_cast<DWORD*>(library_base + export_dir->AddressOfFunctions);


    DWORD func_name_index = 0;
    for (func_name_index = 0; func_name_index < export_dir->NumberOfNames; func_name_index++) {
        const char* str = reinterpret_cast<const char*>(library_base + func_names_array[func_name_index]);
        if (std::string(str) == std::string(lpProcName)) break;
    }
    if (func_name_index > export_dir->NumberOfNames) return NULL;
    WORD ordinal = ordinals_array[func_name_index];
    void* func_addr = reinterpret_cast<void*>(library_base + func_addresses_array[ordinal]);
    return func_addr;
}

int main()
{
    HMODULE k32 = GetModuleHandle2("kernel32.dll");
    void* LoadLibraryA = GetProcAddress2(k32, "LoadLibraryA");
    void* VirtualAlloc = GetProcAddress2(GetModuleHandle2("kernel32.dll"), "VirtualAlloc");
}
