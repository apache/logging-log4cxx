// dll.cpp : Defines the entry point for the DLL application.
//

// Insert your headers here
#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers

#include <windows.h>
#include <crtdbg.h>


BOOL APIENTRY DllMain( HANDLE hModule, 
                       DWORD  ul_reason_for_call, 
                       LPVOID lpReserved
					 )
{
#ifdef _DEBUG
	switch(ul_reason_for_call)
	{
		case DLL_PROCESS_ATTACH:
			// Active l'appel automatique de 
			//_CrtDumpMemoryLeaks à la terminaison du programme
			_CrtSetDbgFlag(_CrtSetDbgFlag(_CRTDBG_REPORT_FLAG)|_CRTDBG_LEAK_CHECK_DF);
		break;
	}
#endif

    return TRUE;
}

