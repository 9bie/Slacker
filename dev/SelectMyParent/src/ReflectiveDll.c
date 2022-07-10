//===============================================================================================//
// This is a stub for the actuall functionality of the DLL.
//===============================================================================================//
#include "ReflectiveLoader.h"
#include<stdio.h>
#include <stdlib.h>
#include <string.h>
#pragma comment(lib,"advapi32.lib")

BOOL CurrentProcessAdjustToken(void)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES sTP;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sTP.Privileges[0].Luid))
		{
			CloseHandle(hToken);
			return FALSE;
		}
		sTP.PrivilegeCount = 1;
		sTP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (!AdjustTokenPrivileges(hToken, 0, &sTP, sizeof(sTP), NULL, NULL))
		{
			CloseHandle(hToken);
			return FALSE;
		}
		CloseHandle(hToken);
		return TRUE;
	}
	return FALSE;
}


// Note: REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR and REFLECTIVEDLLINJECTION_CUSTOM_DLLMAIN are
// defined in the project properties (Properties->C++->Preprocessor) so as we can specify our own 
// DllMain and use the LoadRemoteLibraryR() API to inject this DLL.

// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;
//===============================================================================================//
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved)
{
	char* p = NULL;
	int i = 0;
	char* path = NULL;
	DWORD dwPid;
	BOOL bReturnValue = TRUE;
	switch (dwReason)
	{
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE*)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:

		hAppInstance = hinstDLL;
		if (lpReserved != NULL) {
			STARTUPINFOEX sie = { sizeof(sie) };
			PROCESS_INFORMATION pi;
			SIZE_T cbAttributeListSize = 0;
			PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = NULL;
			HANDLE hParentProcess = NULL;
			DWORD dwPid = 0;
			char* p = strtok((char*)lpReserved," ");
			if (p == NULL) {
				printf("Error param");
				goto end;
			}
			dwPid = atoi(p);
			if (0 == dwPid)
			{
				printf("Invalid pid");
				goto end;
			}
			InitializeProcThreadAttributeList(NULL, 1, 0, &cbAttributeListSize);
			pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, cbAttributeListSize);

			if (NULL == pAttributeList)
			{
				printf("error HeapAlloc\n");
				//DisplayErrorMessage(TEXT("HeapAlloc error"), GetLastError());
				goto end;
			}
			if (!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &cbAttributeListSize))
			{
				//DisplayErrorMessage(TEXT("InitializeProcThreadAttributeList error"), GetLastError());
				goto end;
			}

			CurrentProcessAdjustToken();

			hParentProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
			if (NULL == hParentProcess)
			{
				printf("error openprocess\n");
				//DisplayErrorMessage(TEXT("OpenProcess error"), GetLastError());
				goto end;
			}
			if (!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL))
			{
				printf("error UpdateProcThreadAttribute\n");
				//DisplayErrorMessage(TEXT("UpdateProcThreadAttribute error"), GetLastError());
				goto end;
			}
			sie.lpAttributeList = pAttributeList;
			p = strtok(NULL, " ");
			if (p == NULL) {
				printf("Error param2");
				goto end;
			}
			if (!CreateProcess(NULL, p, NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &sie.StartupInfo, &pi))
			{
				printf("error CreateProcess\n");
				//DisplayErrorMessage(TEXT("CreateProcess error"), GetLastError());
				goto end;
			}
			printf("Process created: %d\n", pi.dwProcessId);
			DeleteProcThreadAttributeList(pAttributeList);
			CloseHandle(hParentProcess);
		}
		else {
			printf("There is no parameter\n");
		}
		
end:
	fflush(stdout);
	ExitProcess(0);


		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}