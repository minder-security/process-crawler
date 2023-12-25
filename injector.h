#include <Windows.h>
#include <string.h>

#include <locale>
#include <codecvt>

int InjectShellcode(int pid, char *shellcode);
int InjectDLL();

// RETURN CODES:
//	0x00 = Success
//  0x01 = Process not found
//  0x02 = No permission to open process
//  0x03 = 
int InjectShellcode(int pid, char *shellcode)
{
	PVOID rBuffer = NULL;
	size_t rBufSize = sizeof(shellcode);
	DWORD dwPID = NULL;
	DWORD dwTID = (DWORD) pid;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	DWORD dwError = NULL;

	// OPEN PROCESS
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);
	if (hProcess == NULL) {
		dwError = GetLastError();

		if (dwError == ERROR_INVALID_PARAMETER) return 0x01;
		if (dwError == ERROR_ACCESS_DENIED) return 0x02;
	}

	// ALLOCATE REMOTE BUFFER
	rBuffer = VirtualAllocEx(hProcess, NULL, rBufSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
	if (rBuffer == NULL) {
		dwError = GetLastError();

		if (dwError == ERROR_ACCESS_DENIED) return 0x02;
	}

	// WRITE SHELLCODE INTO MEMORY
	WriteProcessMemory(hProcess, rBuffer, shellcode, rBufSize, NULL);

	// CREATE THREAT FROM BUFFER
	hThread = CreateRemoteThreadEx(hProcess, NULL, 0x00, (LPTHREAD_START_ROUTINE)rBuffer, 0x00, 0x00, 0x00, &dwTID);


	// WAIT FOR THREAD TO FINISH
	WaitForSingleObject(hThread, INFINITE);


	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 0x00;
}


// RETURN CODES:
//	0x00 = Success
//  0x01 = Process not found
//  0x02 = No permission to open process
//  0x03 = Kernel32.dll not found
int InjectDLL(int pid, char *dll_path)
{
	DWORD       TID = NULL;
	DWORD       PID = pid;
	LPVOID      rBuffer = NULL;
	HANDLE      hProcess = NULL;
	HANDLE      hThread = NULL;
	HMODULE     hKernel32 = NULL;
	wchar_t     dllPath[MAX_PATH];
	size_t      pathSize = sizeof(dllPath);
	size_t      bytesWritten = 0;
	DWORD       dwError = NULL;

	LPTHREAD_START_ROUTINE kawLoadLibrary;


	// Convert Path Argument to Wide String
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::wstring wide = converter.from_bytes(dll_path);
	wcscpy_s(dllPath, MAX_PATH, wide.c_str());

	// OPEN PROCESS HANDLE
	hProcess = OpenProcess((PROCESS_VM_OPERATION | PROCESS_VM_WRITE), FALSE, PID);
	if (hProcess == NULL) {
		dwError = GetLastError();

		if (dwError == ERROR_INVALID_PARAMETER) return 0x01;
		if (dwError == ERROR_ACCESS_DENIED) return 0x02;
	}

	// GET HANDLE TO Kernel32.dll
	hKernel32 = GetModuleHandleW(L"kernel32");
	if (hKernel32 == NULL) goto CLEANUP;

	// GET ADDRESS OF LoadLibraryW
	kawLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");

	// ALLOCATE BUFFER IN TARGET PROCESS
	rBuffer = VirtualAllocEx(hProcess, NULL, pathSize, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	if (rBuffer == NULL) goto CLEANUP;

	// WRITE TO MEMORY
	WriteProcessMemory(hProcess, rBuffer, dllPath, pathSize, &bytesWritten);

	// CREATE THREAD
	hThread = CreateRemoteThread(hProcess, NULL, 0x00, kawLoadLibrary, rBuffer, 0x00, &TID);
	if (hThread == NULL) goto CLEANUP;

	// WAIT FOR THREAT TO FINISH
	WaitForSingleObject(hThread, INFINITE);
	goto CLEANUP;

CLEANUP:
	if (hThread) CloseHandle(hThread);
	if (hProcess) CloseHandle(hProcess);
	return 0;
}