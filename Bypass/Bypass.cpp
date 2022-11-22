#include "DoBypass.h"

auto main(void) -> int
{
	DoBypass* doBypass = new DoBypass();

	const wchar_t ProcName[] =  L"CRACKME.EXE";

	HANDLE hProc = doBypass->AbrirProcessoPeloNome(ProcName);

	uintptr_t ModuleBase = doBypass->GetModuleBaseAddress(doBypass->GetProcessInfo(ProcName), ProcName);

	doBypass->readMemoryOpcodes(hProc, ModuleBase, doBypass->x32PatchAddress, &doBypass->bbyte);

	for (int i = 0; i < static_cast<int>(doBypass->bbyte.size()); i++)
		printf("%X", doBypass->bbyte.at(i));

	doBypass->bbyte.clear();

	doBypass->writeMemoryOpcodes(hProc, ModuleBase, doBypass->x32PatchAddress, doBypass->x32AssemblyOpcodes);

	printf("\nSuccess!!");

	return 0;
}