#include <iostream>
#include <windows.h>
#include <vector>
#include <TlHelp32.h>

#pragma once

class DoBypass
{
public:

	std::vector <unsigned int> x32PatchAddress = { 0x1243 };

	std::vector <unsigned int> x32AssemblyOpcodes = { 0x75 };

	std::vector <uint8_t> bbyte;


	auto GetProcessInfo(const wchar_t* processo) -> DWORD;

	auto AbrirProcessoPeloNome(const wchar_t* processo) -> HANDLE;

	auto GetModuleBaseAddress(DWORD procId, const wchar_t* modName) -> uintptr_t;

	auto readMemoryOpcodes(HANDLE hProcess, uintptr_t moduleBase, std::vector<unsigned int>x32PatchAddress, std::vector<uint8_t>* bbyte) -> void;

	auto writeMemoryOpcodes(HANDLE hProcess, uintptr_t moduleBase, std::vector<unsigned int>x32PatchAddress, std::vector<unsigned int>x32AssemblyOpcodes) -> void;
};

