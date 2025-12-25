#include <iostream>
#include <windows.h>
#include <winternl.h>
#include <string.h>

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
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    std::cout << GetProcAddress2(k32, "GetProcAddress") << std::endl;
    std::cout << GetProcAddress(k32, "GetProcAddress") << std::endl;
}
