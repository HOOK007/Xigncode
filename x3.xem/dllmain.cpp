#include "stdafx.h"

BOOL APIENTRY DllMain(__in HINSTANCE hInstance, __in DWORD fdwReason, __reserved LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		srand(GetTickCount());
		srand(rand());
		DisableThreadLibraryCalls(hInstance);
	}
	else if (fdwReason == DLL_PROCESS_DETACH)
	{
	}
	return TRUE;
}