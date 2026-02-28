#include <ShlObj.h>
#include <Winternl.h>


ULONG PseudoRand(ULONG* seed)
{
	return (*seed = 1352459 * (*seed) + 2529004207);
}

void GetBotId(char* botId)
{
	CHAR windowsDirectory[MAX_PATH];
	CHAR volumeName[8] = { 0 };
	DWORD seed = 0;

	if (GetWindowsDirectoryA(windowsDirectory, sizeof(windowsDirectory)))
		windowsDirectory[0] = L'C';

	volumeName[0] = windowsDirectory[0];
	volumeName[1] = ':';
	volumeName[2] = '\\';
	volumeName[3] = '\0';

	GetVolumeInformationA(volumeName, NULL, 0, &seed, 0, NULL, NULL, 0);

	GUID guid;
	guid.Data1 = PseudoRand(&seed);

	guid.Data2 = (USHORT)PseudoRand(&seed);
	guid.Data3 = (USHORT)PseudoRand(&seed);
	for (int i = 0; i < 8; i++)
		guid.Data4[i] = (UCHAR)PseudoRand(&seed);

	wsprintfA(botId, (PCHAR)"%08lX%04lX%lu", guid.Data1, guid.Data3, *(ULONG*)& guid.Data4[2]);
}




void* Alloc(size_t size)
{
	void* mem =malloc(size);
	return mem;
}

#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget)
{
	unsigned char* p = static_cast<unsigned char*>(pTarget);
	while (cbTarget-- > 0)
	{
		*p++ = static_cast<unsigned char>(value);
	}
	return pTarget;
}






void CopyDir(char* from, char* to)
{
	char fromWildCard[MAX_PATH] = { 0 };
	lstrcpyA(fromWildCard, from);
	lstrcatA(fromWildCard, (PCHAR)"\\*");

	if (!CreateDirectoryA(to, NULL) && GetLastError() != ERROR_ALREADY_EXISTS)
		return;
	WIN32_FIND_DATAA findData;
	HANDLE hFindFile = FindFirstFileA(fromWildCard, &findData);
	if (hFindFile == INVALID_HANDLE_VALUE)
		return;

	do
	{
		char currFileFrom[MAX_PATH] = { 0 };
		lstrcpyA(currFileFrom, from);
		lstrcatA(currFileFrom, (PCHAR)"\\");
		lstrcatA(currFileFrom, findData.cFileName);

		char currFileTo[MAX_PATH] = { 0 };
		lstrcpyA(currFileTo, to);
		lstrcatA(currFileTo, (PCHAR)"\\");
		lstrcatA(currFileTo, findData.cFileName);

		if
			(
				findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY &&
				lstrcmpA(findData.cFileName, (PCHAR)".") &&
				lstrcmpA(findData.cFileName, (PCHAR)"..")
				)
		{
			if (CreateDirectoryA(currFileTo, NULL) || GetLastError() == ERROR_ALREADY_EXISTS)
				CopyDir(currFileFrom, currFileTo);
		}
		else
			CopyFileA(currFileFrom, currFileTo, FALSE);
	} while (FindNextFileA(hFindFile, &findData));
}
