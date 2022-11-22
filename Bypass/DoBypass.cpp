#include "DoBypass.h"

auto DoBypass::GetProcessInfo(const wchar_t* processo) -> DWORD
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    pe32.dwSize = sizeof(PROCESSENTRY32);

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    do {
        if (wcscmp(pe32.szExeFile, processo) == 0)
        {
            CloseHandle(hProcessSnap);

            return pe32.th32ProcessID;
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return 0;
}

auto DoBypass::AbrirProcessoPeloNome(const wchar_t* processo) -> HANDLE
{
    return OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetProcessInfo(processo));
}

uintptr_t DoBypass::GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
{
    uintptr_t modBaseAddr = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 modEntry;
        modEntry.dwSize = sizeof(modEntry);
        if (Module32First(hSnap, &modEntry))
        {
            do
            {
                if (!_wcsicmp(modEntry.szModule, modName))
                {
                    modBaseAddr = (uintptr_t)modEntry.modBaseAddr;

                    break;
                }
            } while (Module32Next(hSnap, &modEntry));
        }
    }

    CloseHandle(hSnap);

    return modBaseAddr;
}

void DoBypass::readMemoryOpcodes(HANDLE hProcess, uintptr_t moduleBase, std::vector<unsigned int>x32PatchAddress, std::vector<uint8_t>* bbyte)
{
    uintptr_t val = 0;

    for (unsigned int x : x32PatchAddress) 
    {
        val = moduleBase + x;
        uint8_t local = 0;
    
        ReadProcessMemory(hProcess, (void*)val, &local, sizeof(uint8_t), 0);
        
        (*bbyte).push_back(local);
    }
}

void DoBypass::writeMemoryOpcodes(HANDLE hProcess, uintptr_t moduleBase, std::vector<unsigned int>x32PatchAddress, std::vector<unsigned int>x32AssemblyOpcodes)
{
    uintptr_t val = 0;

    for (int i = 0; i < static_cast<int>(x32AssemblyOpcodes.size()); i++) 
    {
        val = moduleBase + x32PatchAddress.at(i);

        WriteProcessMemory(hProcess, (void*)val, &x32AssemblyOpcodes.at(i), sizeof(unsigned char), 0);
    }
}