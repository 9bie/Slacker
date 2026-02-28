#pragma once
/* some code and/or ideas are from trustedsec SA Github repo -- thankyou trustedsec! */
#include <windows.h>

#include "beacon.h"

void go(char* buff, int len);

#define WINBOOL BOOL


typedef struct _STARTUPINFOEXA2 {
    STARTUPINFOA StartupInfo;
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} STARTUPINFOEXA2, * LPSTARTUPINFOEXA2;



#define intZeroMemory(addr,size) MSVCRT$memset((addr),0,size)



DECLSPEC_IMPORT WINBASEAPI void __cdecl   MSVCRT$memset(void* dest, int c, size_t count);
DECLSPEC_IMPORT WINBASEAPI void* __cdecl  MSVCRT$memcpy(void* dest, const void* src, size_t count);
DECLSPEC_IMPORT WINBASEAPI int __cdecl    MSVCRT$strcmp(const char* _Str1, const char* _Str2);
DECLSPEC_IMPORT WINBASEAPI size_t __cdecl MSVCRT$strlen(const char* _Str);
DECLSPEC_IMPORT WINBASEAPI int __cdecl    MSVCRT$sscanf_s(const char* _Src, const char* _Format, ...);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, WINBOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI  KERNEL32$VirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI  KERNEL32$CreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
// DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI   KERNEL32$QueueUserAPC (PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR dwData);
// DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI   KERNEL32$ResumeThread (HANDLE hThread);
DECLSPEC_IMPORT WINBASEAPI DWORD WINAPI   KERNEL32$GetLastError(VOID);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$SetEnvironmentVariableA(LPCSTR lpName, LPCSTR lpValue);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$CloseHandle(HANDLE hObject);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI  KERNEL32$CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, WINBOOL bInitialOwner, LPCSTR lpName);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI  KERNEL32$OpenMutexA(DWORD dwDesiredAccess, WINBOOL bInheritHandle, LPCSTR lpName);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$CreatePipe(PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);
DECLSPEC_IMPORT WINBASEAPI WINBOOL WINAPI KERNEL32$ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI  KERNEL32$CreateFileMappingA(HANDLE hFile, LPSECURITY_ATTRIBUTES lpFileMappingAttributes, DWORD flProtect, DWORD dwMaximumSizeHigh, DWORD dwMaximumSizeLow, LPCSTR lpName);
DECLSPEC_IMPORT WINBASEAPI LPVOID WINAPI  KERNEL32$MapViewOfFile(HANDLE hFileMappingObject, DWORD dwDesiredAccess, DWORD dwFileOffsetHigh, DWORD dwFileOffsetLow, SIZE_T dwNumberOfBytesToMap);
DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI  KERNEL32$OpenFileMappingA(DWORD dwDesiredAccess, BOOL bInheritHandle, LPCSTR lpName);





/* MyAPIFunction*/

DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CreateProcessA(
LPCSTR                lpApplicationName,
LPSTR                 lpCommandLine,
LPSECURITY_ATTRIBUTES lpProcessAttributes,
LPSECURITY_ATTRIBUTES lpThreadAttributes,
BOOL                  bInheritHandles,
DWORD                 dwCreationFlags,
LPVOID                lpEnvironment,
LPCSTR                lpCurrentDirectory,
LPSTARTUPINFOA        lpStartupInfo,
LPPROCESS_INFORMATION lpProcessInformation
);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$GetThreadContext(
HANDLE    hThread,
LPCONTEXT lpContext
);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$ReadProcessMemory(
HANDLE  hProcess,
LPCVOID lpBaseAddress,
LPVOID  lpBuffer,
SIZE_T  nSize,
SIZE_T* lpNumberOfBytesRead
);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(
HMODULE hModule,
LPCSTR  lpProcName
);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$GetModuleHandleA(
LPCSTR lpModuleName
);
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$VirtualAllocEx(
HANDLE hProcess,
LPVOID lpAddress,
SIZE_T dwSize,
DWORD  flAllocationType,
DWORD  flProtect
);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$WriteProcessMemory(
HANDLE  hProcess,
LPVOID  lpBaseAddress,
LPCVOID lpBuffer,
SIZE_T  nSize,
SIZE_T* lpNumberOfBytesWritten
);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$SetThreadContext(
HANDLE        hThread,
const CONTEXT* lpContext
);
DECLSPEC_IMPORT DWORD WINAPI KERNEL32$ResumeThread(
HANDLE hThread
);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$CloseHandle(
HANDLE hObject
);

#define fnmemset MSVCRT$memset
#define fnmemcpy MSVCRT$memcpy
#define fnCloseHandle KERNEL32$CloseHandle
#define fnResumeThread KERNEL32$ResumeThread
#define fnSetThreadContext KERNEL32$SetThreadContext
#define fnWriteProcessMemory KERNEL32$WriteProcessMemory
#define fnVirtualAllocEx KERNEL32$VirtualAllocEx
#define fnGetModuleHandleA KERNEL32$GetModuleHandleA
#define fnGetProcAddress KERNEL32$GetProcAddress
#define fnReadProcessMemory KERNEL32$ReadProcessMemory
#define fnGetThreadContext KERNEL32$GetThreadContext
#define fnCreateProcessA KERNEL32$CreateProcessA