// Test.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>


int _tmain(int argc, _TCHAR* argv[])
{
	char szCmdLine[MAX_PATH] = { 0 };
	char szRundll32Path[MAX_PATH] = "C:\\Windows\\System32\\rundll32.exe";
	char szDllPath[MAX_PATH] = "C:\\Users\\DemonGan\\Desktop\\BypassUAC2_Test\\Debug\\BypassUAC2_Test.dll";
	::sprintf_s(szCmdLine, "%s \"%s\" %s", szRundll32Path, szDllPath, "BypassUAC");
	::WinExec(szCmdLine, SW_HIDE);

	printf("Run OK.\n");
	system("pause");
	return 0;
}

