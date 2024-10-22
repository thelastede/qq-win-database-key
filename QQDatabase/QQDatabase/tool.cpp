#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <tchar.h>
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <io.h>


const char* nt_sqlite3_key_v2_pattern = "nt_sqlite3_key_v2: db=%p zDb=%s";
WCHAR targetFileFullPath[MAX_PATH];
char* fileContent;


void* memmem(const void* l, size_t l_len, const void* s, size_t s_len)
{
	register char* cur, * last;
	const char* cl = (const char*)l;
	const char* cs = (const char*)s;

	/* we need something to compare */
	if (l_len == 0 || s_len == 0)
		return NULL;

	/* "s" must be smaller or equal to "l" */
	if (l_len < s_len)
		return NULL;

	/* special case where s_len == 1 */
	if (s_len == 1)
		return (void*)memchr(l, (int)*cs, l_len);

	/* the last position where its possible to find "s" in "l" */
	last = (char*)cl + l_len - s_len;

	for (cur = (char*)cl; cur <= last; cur++)
		if (cur[0] == cs[0] && memcmp(cur, cs, s_len) == 0)
			return cur;

	return NULL;
}



/*
PE�ļ����ڴ�ƫ�����ļ�ƫ���໥ת��,������ϵͳΪ�������ƫ��ת��
*/
DWORD AddressConvert(DWORD dwAddr, BOOL bFile2RVA)
{
	char* lpBase = fileContent;
	DWORD dwRet = -1;
 
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)lpBase;
	PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((unsigned long long)lpBase + pDosHeader->e_lfanew);

	DWORD dwMemAlign = pNtHeader->OptionalHeader.SectionAlignment;
	DWORD dwFileAlign = pNtHeader->OptionalHeader.FileAlignment;
	int dwSecNum = pNtHeader->FileHeader.NumberOfSections;
	PIMAGE_SECTION_HEADER pSecHeader = (PIMAGE_SECTION_HEADER)((char*)lpBase + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	DWORD dwHeaderSize = 0;

	if (!bFile2RVA)  // �ڴ�ƫ��ת��Ϊ�ļ�ƫ��  
	{
		//����Ҫת�Ƶ�ƫ���Ƿ���PEͷ�ڣ������������ƫ����ͬ  
		dwHeaderSize = pNtHeader->OptionalHeader.SizeOfHeaders;
		if (dwAddr <= dwHeaderSize)
		{
			delete lpBase;
			lpBase = NULL;
			return dwAddr;
		}
		else //����PEͷ��鿴�õ�ַ���ĸ�������  
		{
			for (int i = 0; i < dwSecNum; i++)
			{
				DWORD dwSecSize = pSecHeader[i].Misc.VirtualSize;
				if ((dwAddr >= pSecHeader[i].VirtualAddress) && (dwAddr <= pSecHeader[i].VirtualAddress + dwSecSize))
				{
					//�ҵ��ø�ƫ�ƣ����ļ�ƫ�� = ��������ļ�ƫ�� + ����ƫ�� - ��������ڴ�ƫ�ƣ�  
					dwRet = pSecHeader[i].PointerToRawData + dwAddr - pSecHeader[i].VirtualAddress;
				}
			}
		}
	}
	else // �ļ�ƫ��ת��Ϊ�ڴ�ƫ��  
	{
		dwHeaderSize = pNtHeader->OptionalHeader.SizeOfHeaders;
		//����Ҫת�Ƶ�ƫ���Ƿ���PEͷ�ڣ������������ƫ����ͬ  
		if (dwAddr <= dwHeaderSize)
		{
			delete lpBase;
			lpBase = NULL;
			return dwAddr;
		}
		else//����PEͷ��鿴�õ�ַ���ĸ�������  
		{
			for (int i = 0; i < dwSecNum; i++)
			{
				DWORD dwSecSize = pSecHeader[i].Misc.VirtualSize;
				if ((dwAddr >= pSecHeader[i].PointerToRawData) && (dwAddr <= pSecHeader[i].PointerToRawData + dwSecSize))
				{
					//�ҵ��ø�ƫ�ƣ����ڴ�ƫ�� = ��������ڴ�ƫ�� + ����ƫ�� - ��������ļ�ƫ�ƣ�  
					dwRet = pSecHeader[i].VirtualAddress + dwAddr - pSecHeader[i].PointerToRawData;
				}
			}
		}
	}

	//�ͷ��ڴ�  
	return dwRet;
}


void GetProcessFilePath(DWORD processID, WCHAR* processFilePath) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

	if (hProcess != NULL) {
		// ��ȡ���̵���ģ��·��
		if (GetModuleFileNameEx(hProcess, NULL, processFilePath, MAX_PATH)) {
			_tprintf(TEXT("[*] Process ID: %u\n"), processID);
			_tprintf(TEXT("[*] Process Path: %s\n"), processFilePath);
		}
		else {
			_tprintf(TEXT("[x] Failed to get module file name for process %u.\n"), processID);
		}
		CloseHandle(hProcess);
	}
	else {
		_tprintf(TEXT("[x] Failed to open process %u.\n"), processID);
	}
}

// ���������б�����QQ.exe����ȡ���ļ�·��
void FindQQProcess(WCHAR* processFilePath) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		_tprintf(TEXT("[x] Failed to take snapshot of processes.\n"));
		return;
	}

	// ���������б�
	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (_tcsicmp(pe32.szExeFile, _T("QQ.exe")) == 0) {
				_tprintf(TEXT("[!] Found QQ.exe with PID: %u\n"), pe32.th32ProcessID);
				GetProcessFilePath(pe32.th32ProcessID, processFilePath);  // ��ȡQQ.exe���ļ�·��
				break;
			}
		} while (Process32Next(hSnapshot, &pe32));
	}
	else {
		_tprintf(TEXT("[!] Failed to retrieve first process.\n"));
	}

	CloseHandle(hSnapshot);
}

void KillQQProcess() {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe;
	pe.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnapshot, &pe)) {
		do {
			if (_tcsicmp(pe.szExeFile, _T("QQ.exe")) == 0) {
				HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, 0, pe.th32ProcessID);
				if (hProcess) {
					TerminateProcess(hProcess, 0);
					CloseHandle(hProcess);
				}
			}
		} while (Process32Next(hSnapshot, &pe));
	}
	CloseHandle(hSnapshot);
}

bool SearchFiles(const WCHAR* directory, const WCHAR* targetFile) {
	WIN32_FIND_DATA findFileData;
	HANDLE hFind = INVALID_HANDLE_VALUE;
	WCHAR fullPath[MAX_PATH];
	WCHAR searchPattern[MAX_PATH];

	// ƴ������ģʽ��������ǰĿ¼�µ������ļ�����Ŀ¼
	_stprintf_s(searchPattern, MAX_PATH, _T("%s\\*"), directory);

	// ���ҵ�һ���ļ���Ŀ¼
	hFind = FindFirstFile(searchPattern, &findFileData);
	if (hFind == INVALID_HANDLE_VALUE) {
		_tprintf(_T("[x] Invalid file handle. Error: %u\n"), GetLastError());
		return 0;
	}

	do {
		// ���� "." �� ".." Ŀ¼
		if (_tcscmp(findFileData.cFileName, _T(".")) != 0 && _tcscmp(findFileData.cFileName, _T("..")) != 0) {
			// �����������ļ�·��
			_stprintf_s(fullPath, MAX_PATH, _T("%s\\%s"), directory, findFileData.cFileName);

			// ����ҵ�������Ŀ¼���ݹ���ú���
			if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if (SearchFiles(fullPath, targetFile) != 0)
					return 1;
			}
			else {
				// ������ļ�������ļ����Ƿ���Ŀ���ļ�ƥ��
				if (_tcscmp(findFileData.cFileName, targetFile) == 0) {
					_tprintf(_T("[!] Found target file: %s\n"), fullPath);
					memcpy(targetFileFullPath, fullPath, MAX_PATH);
					return 1;
				}
			}
		}
	} while (FindNextFile(hFind, &findFileData) != 0);

	// �رղ��Ҿ��
	FindClose(hFind);
	return 0;
}

size_t FindPatternInFile(HANDLE hFile, const char* pattern, size_t patternLen) {
	char buffer[4096];
	DWORD bytesRead;
	size_t offset = 0;

	while (ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL) && bytesRead > 0) {
		char* ptr = (char*)memmem(buffer, bytesRead, pattern, patternLen);
		if (ptr) {
			return offset + (ptr - buffer);
		}
		offset += bytesRead;
	}
	return -1; // Pattern not found
}

DWORD getNum(char* buffer)
{
	DWORD res = 0;
	for (int i = 3; i >= 0; i--)
	{
		res += (buffer[i] & 0xff) << (i * 8);
	}
	return res;
}


DWORD findTargetCode(HANDLE hFile, DWORD fileOffset, DWORD RVA)
{
	DWORD strRVA = AddressConvert(fileOffset, 1);
	_tprintf(TEXT("[*] Targe string RVA: %x\n"), strRVA);
	char buffer[4096];
	const char* pattern = "\x48\x8D\x15"; // lea rdx xxxxx
	const char* pushPattern = "\x48\x83\xec";
	DWORD bytesRead;
	DWORD curFileoffset = 0;
	size_t offset = 0;
	BOOL res = 1;

	LARGE_INTEGER li;
	li.QuadPart = 0;  // ƫ����Ϊ0�����ƶ����ļ���ʼ
	SetFilePointerEx(hFile, li, NULL, FILE_BEGIN);

	while ((res = ReadFile(hFile, buffer, sizeof(buffer), &bytesRead, NULL)) && bytesRead > 0) {
		char* ptr = buffer;
		while (ptr != 0)
		{
			ptr = (char*)memmem(ptr, bytesRead - (ptr - buffer), pattern, 3);
			if (ptr) {
				curFileoffset = offset + (ptr - buffer);
				DWORD codeRVA = AddressConvert(curFileoffset, 1);
				DWORD opAddr = getNum(ptr + 3);
				//_tprintf(TEXT("Lea code RVA: %x\n"), codeRVA);
				if (codeRVA + 7 + opAddr == strRVA)
				{
					char* originPtr = ptr;
					char* pushPtr = ptr;
					while (ptr--)
					{
						pushPtr = (char*)memmem(ptr, originPtr - ptr, pushPattern, 3);
						if (pushPtr)
						{
							codeRVA = AddressConvert(offset + (pushPtr - buffer), 1);
							_tprintf(TEXT("[*] Targe code RVA: %x\n"), codeRVA);
							return codeRVA;
						}

					}
				}
				ptr = ptr + 1;
			}
		}
		offset += bytesRead;
	}
next:



	return -1; // Pattern not found


}

void init()
{
	FILE* fp = _wfopen(targetFileFullPath, L"rb");
	fseek(fp, 0, SEEK_END);
	DWORD dwFileSize = ftell(fp);
	fileContent = new char[dwFileSize];
	memset(fileContent, 0, dwFileSize);
	fseek(fp, 0, SEEK_SET);
	fread(fileContent, 1, dwFileSize, fp);
	fclose(fp);
}

DWORD FindQQParentProcess() {
	DWORD parentPID;
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);
	_tprintf(TEXT("[!] Waiting for QQ.\n"));
	while (TRUE) {
		// �������̿���
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			_tprintf(TEXT("[x] Failed to take process snapshot.\n"));
			return 0;
		}

		// ���������б�
		if (Process32First(hSnapshot, &pe32)) {
			do {
				// ���������Ƿ�Ϊ QQ.exe
				if (_tcsicmp(pe32.szExeFile, _T("QQ.exe")) == 0) {
					int parentFound = FALSE;
					// Ѱ�� QQ.exe ������
					//_tprintf(TEXT("Found QQ.exe with PID: %d\n"), pe32.th32ProcessID);
					DWORD parentProcessId = pe32.th32ParentProcessID;
					//_tprintf(TEXT("Parent Pid: %d\n"), parentProcessId);

					// ���Ҹ�������
					HANDLE hParentSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
					PROCESSENTRY32 parentPe32;
					parentPe32.dwSize = sizeof(PROCESSENTRY32);

					if (Process32First(hParentSnapshot, &parentPe32)) {
						do {
							if (parentPe32.th32ProcessID == parentProcessId) {
								if (!_tcsicmp(parentPe32.szExeFile, _T("QQ.exe")))
								{
									_tprintf(TEXT("[!] Parent QQ.EXE Pid: %d\n"), parentPe32.th32ProcessID);
									parentPID = parentPe32.th32ProcessID;
									parentFound = TRUE;
									return parentPe32.th32ProcessID;
								}
								else
								{
									parentFound = FALSE;
									break;
								}

							}
						} while (Process32Next(hParentSnapshot, &parentPe32));
					}

					CloseHandle(hParentSnapshot);

					if (parentFound)
						break;
				}
			} while (Process32Next(hSnapshot, &pe32));
		}
		else {
			_tprintf(TEXT("[x] Failed to retrieve first process.\n"));
		}

		CloseHandle(hSnapshot);

		// �ȴ�һ��ʱ����ٴμ��
		Sleep(1000); // ÿ����һ��
	}
}

BOOL AttachDebuggerToProcess(DWORD processId) {
	if (!DebugActiveProcess(processId)) {
		printf("[x] Failed to attach debugger to process. Error: %u\n", GetLastError());
		return FALSE;
	}
	printf("[!] Debugger attached to process %u.\n", processId);
	return TRUE;
}

DWORD_PTR GetModuleBaseAddress(DWORD processId, const TCHAR* moduleName) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		printf("[x] Failed to create snapshot. Error: %u\n", GetLastError());
		return 0;
	}

	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(hSnapshot, &moduleEntry)) {
		do {
			if (_tcsicmp(moduleEntry.szModule, moduleName) == 0) {
				CloseHandle(hSnapshot);
				_tprintf(TEXT("[!] Found module %s at base address: 0x%p\n"), moduleName, moduleEntry.modBaseAddr);
				return (DWORD_PTR)moduleEntry.modBaseAddr;
			}
		} while (Module32Next(hSnapshot, &moduleEntry));
	}

	printf("[x] Module %s not found.\n", moduleName);
	CloseHandle(hSnapshot);
	return 0;
}

BYTE SetBreakpoint(HANDLE hProcess, DWORD_PTR address) {
	BYTE int3 = 0xCC; // INT 3 ָ��
	SIZE_T bytesWritten;
	SIZE_T bytesRead;
	LPCVOID buffer[4];

	if (!ReadProcessMemory(hProcess, (LPCVOID)address, buffer, 1, &bytesRead)) {
		printf("[x] Failed to read memory. Error: %u\n", GetLastError());
		return FALSE;
	}
	if (!WriteProcessMemory(hProcess, (LPVOID)address, &int3, sizeof(int3), &bytesWritten) || bytesWritten != sizeof(int3)) {
		printf("[x] Failed to set breakpoint. Error: %u\n", GetLastError());
		return FALSE;
	}
	printf("[!] Breakpoint set at address: 0x%p\n", address);
	return ((BYTE *)buffer)[0];
}

BOOL RestoreBreakpoint(HANDLE hProcess, DWORD_PTR address, BYTE instruct) {
	SIZE_T bytesWritten;

	if (!WriteProcessMemory(hProcess, (LPVOID)address, &instruct, sizeof(instruct), &bytesWritten) || bytesWritten != sizeof(instruct)) {
		printf("[x] Failed to set breakpoint. Error: %u\n", GetLastError());
		return FALSE;
	}
	printf("[!] Breakpoint restore at address: 0x%p\n", address);
	return TRUE;
}


BOOL ReadProcessMemoryAndCheck(HANDLE hProcess, LPCVOID baseAddress) {
	const int keyLen = 16;
	BYTE buffer[keyLen+1];
	SIZE_T bytesRead;

	if (!ReadProcessMemory(hProcess, baseAddress, buffer, sizeof(buffer), &bytesRead)) {
		printf("[x] Failed to read process memory. Error: %u\n", GetLastError());
		return FALSE;
	}

	if (bytesRead != sizeof(buffer)) {
		printf("[x] Could not read all 32 bytes. Read %llu bytes instead.\n", bytesRead);
		return FALSE;
	}

	// ���� 33 ���ֽ��Ƿ�Ϊ \x00
	if (strlen((const char *)buffer) != keyLen) {
		printf("[x] keylen is not equal to %d\n",keyLen);
		return FALSE;
	}

	printf("*****************************************************************************************************\n[!!!] Found database key:\n");
	printf("Hex data:");
	for (int i = 0; i < keyLen; i++)
		printf("0x%x ", buffer[i]);
	printf("\n");
	printf("Ascii data:");
	for (int i = 0; i < keyLen; i++)
		printf("%c", buffer[i]);
	printf("\n*****************************************************************************************************\n");
	FILE* fp = fopen("password.txt", "w");
	fwrite(buffer, 1, keyLen, fp);
	fclose(fp);
	return TRUE;
}

BOOL ContinueAndDetach(DWORD processId) {
	// ����ֹͣ����������
	if (!DebugActiveProcessStop(processId)) {
		printf("[x] Failed to detach debugger from process %lu. Error: %lu\n", processId, GetLastError());
		return FALSE;
	}

	printf("[!] Debugger successfully detached from process %lu.\n", processId);
	return TRUE;
}

BOOL SuspendProcess(DWORD processID) {
	// ��ȡָ�����̵Ŀ���
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		_tprintf(_T("[x] CreateToolhelp32Snapshot failed: %u\n"), GetLastError());
		return FALSE;
	}

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	// ö�ٿ����е��߳�
	if (Thread32First(hSnapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == processID) {
				// �򿪸��߳�
				HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
				if (hThread == NULL) {
					_tprintf(_T("[x] Failed to open thread: %u\n"), GetLastError());
					CloseHandle(hSnapshot);
					return FALSE;
				}

				// ������߳�
				SuspendThread(hThread);
				CloseHandle(hThread);
			}
		} while (Thread32Next(hSnapshot, &threadEntry));
	}

	CloseHandle(hSnapshot);
	return TRUE;
}

BOOL ResumeProcess(DWORD processID) {
	// ��ȡָ�����̵Ŀ���
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		_tprintf(_T("[x] CreateToolhelp32Snapshot failed: %u\n"), GetLastError());
		return FALSE;
	}

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	// ö�ٿ����е��߳�
	if (Thread32First(hSnapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == processID) {
				// �򿪸��߳�
				HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
				if (hThread == NULL) {
					_tprintf(_T("[x] Failed to open thread: %u\n"), GetLastError());
					CloseHandle(hSnapshot);
					return FALSE;
				}

				// �ָ����߳�
				ResumeThread(hThread);
				CloseHandle(hThread);
			}
		} while (Thread32Next(hSnapshot, &threadEntry));
	}

	CloseHandle(hSnapshot);
	return TRUE;
}

void WaitForBreakpointAndReadPassword(HANDLE hProcess, DWORD_PTR address, DWORD QQPid) {
	DEBUG_EVENT debugEvent;
	CONTEXT context;
	context.ContextFlags = CONTEXT_ALL;

	// ��ȡ����
	while (TRUE) {
		// �ȴ������¼�
		if (WaitForDebugEvent(&debugEvent, INFINITE)) {
			// ��Ҫ�Ƕϵ��¼�
			if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
				debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {

				// ������ַ���¶ϵ�ĵ�ַ�Բ��Ե���
				if ((unsigned long long)address != (unsigned long long)debugEvent.u.Exception.ExceptionRecord.ExceptionAddress)
				{
					ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
					continue;
				}

				// ��ַ�����ˣ�������̱��⾺��
				printf("[!] Breakpoint hit at address: 0x%p\n", debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
				SuspendProcess(QQPid);

				HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, debugEvent.dwThreadId);
				if (hThread) {
					// ��ȡ�߳�������
					if (GetThreadContext(hThread, &context)) {
						printf("[*] r8 value: 0x%llx\n", context.R8);
						// ȷ����Կ�Ƿ�Ϊ��Ҫ�ĸ�ʽ
						if (ReadProcessMemoryAndCheck(hProcess, (LPCVOID)context.R8))
						{
							// �ָ��ϵ㣬����RIP���ָ��߳������ģ��������ԣ��ָ�����
							RestoreBreakpoint(hProcess, address, 0x48);
							context.Rip -= 1;
							SetThreadContext(hThread, &context);
							ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
							CloseHandle(hThread);
							ResumeProcess(QQPid);
							return;
						}
						// �����Կ��ʽ���ԣ�������һ��ָ���¶ϵ㣬��ִ�й�ȥ���������������ٸոյ�λ���¶ϵ㣬Ȼ����ָ�����ִ��
						else
						{
							// ����һ��ָ���¶ϵ㣬��������д���ֽ�
							BYTE targetByte = SetBreakpoint(hProcess, (DWORD_PTR)((unsigned long long)address) + 4);
							if (!targetByte) {
								printf("[!] Set breakpoint failed with %d\n", GetLastError());
								CloseHandle(hProcess);
								return;
							}
							// �ָ�ԭĿ��ָ��ϵ㣬����RIP���ָ��߳������ģ��������ԣ��ָ�����
							RestoreBreakpoint(hProcess, address, 0x48);
							context.Rip -= 1;
							SetThreadContext(hThread, &context);
							ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
							CloseHandle(hThread);
							ResumeProcess(QQPid);

							// �ȵ���һ���ϵ������
							while (true)
							{
								// �ȵ����¼�
								if (WaitForDebugEvent(&debugEvent, INFINITE)) {
									if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
										debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {

										// ����ַ�Բ��Ե���
										if (((unsigned long long)address) + 4 != (unsigned long long)debugEvent.u.Exception.ExceptionRecord.ExceptionAddress)
										{
											printf("[x] Breakpoint hit at address: 0x%p. Not as expected \n", debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
											ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
											continue;
										}

										printf("[!] Breakpoint hit at address: 0x%p.\n", debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
										// �������
										SuspendProcess(QQPid);

										// ���½����̶߳�����Ϊ���������߳�
										HANDLE hhThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, debugEvent.dwThreadId);
										if (hhThread)
										{
											// ���½�����������Ϣ����Ϊ���������߳�
											CONTEXT ccontext;
											ccontext.ContextFlags = CONTEXT_ALL;
											if (GetThreadContext(hhThread, &ccontext))
											{
												// ��Ŀ��ָ��¶ϵ�
												if (!SetBreakpoint(hProcess, address)) {
													printf("[!] Set breakpoint failed with %d\n", GetLastError());
													CloseHandle(hProcess);
													return;
												}
												// �ָ���ǰ�ϵ㣬�ָ�RIP���ָ��߳������ģ��������ԣ��ָ�����ִ��
												RestoreBreakpoint(hProcess, (DWORD_PTR)((unsigned long long)address) + 4, targetByte);
												ccontext.Rip -= 1;
												SetThreadContext(hhThread, &ccontext);
												ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
												CloseHandle(hhThread);
												ResumeProcess(QQPid);
												break;
											}
											else
											{
												// �����Ļ�ȡʧ�ܣ��������Բ��ָ�����
												printf("[x] Failed to get thread context. Error: %u\n", GetLastError());
												ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
												ResumeProcess(QQPid);
											}

										}
										else
										{
											// �̴߳�ʧ�ܣ��������Բ��ָ�����
											printf("[x] Failed to open thread. Error: %u\n", GetLastError());
											ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
											ResumeProcess(QQPid);
										}
									}
									else
									{
										// ���Ƕϵ��¼��͵���һ��
										ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
										ResumeProcess(QQPid);
									}
								}
							}
						}
					}
					// �����Ļ�ȡʧ�ܣ��������Բ��ָ�����
					else {
						printf("[x] Failed to get thread context. Error: %u\n", GetLastError());
						ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
						ResumeProcess(QQPid);
					}
				}
				// �̴߳�ʧ�ܣ��������Բ��ָ�����
				else
				{
					printf("[x] Failed to open thread. Error: %u\n", GetLastError());
					ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
					ResumeProcess(QQPid);
				}
			}
			// ���Ƕϵ��¼��͵���һ��
			else
				ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
		}
	}
}

int main()
{
	WCHAR processFilePath[MAX_PATH] = TEXT("<unknown>");
	HANDLE targetFileHandle = 0;
	DWORD codeRVA = 0;
	DWORD fileOffset = 0;

	// �ҵ�Ŀ���ļ�·������ 
	FindQQProcess(processFilePath);
	WCHAR* lastBackslash = wcsrchr(processFilePath, L'\\');
	if (lastBackslash != NULL) {
		*lastBackslash = L'\0';
	}
	if (!SearchFiles(processFilePath, L"wrapper.node"))
	{
		_tprintf(TEXT("[x] wrapper.node not found"));
		return 0;
	}
	init();

	targetFileHandle = CreateFile(targetFileFullPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (targetFileHandle == INVALID_HANDLE_VALUE)
	{
		_tprintf(TEXT("[x] File open failed with %d"), GetLastError());
		return 0;
	}

	// ��ȡĿ���ַ����ļ�ƫ��
	fileOffset = FindPatternInFile(targetFileHandle, nt_sqlite3_key_v2_pattern, strlen(nt_sqlite3_key_v2_pattern));
	_tprintf(_T("[!] Found nt_sqlite3_key_v2_pattern offset: %x\n"), fileOffset);

	// ����Ŀ�����
	codeRVA = findTargetCode(targetFileHandle, fileOffset, codeRVA);
	if (codeRVA == -1)
	{
		_tprintf(_T("[x] Target code not found: \n"));
		return 0;
	}
	CloseHandle(targetFileHandle);
	// �ر�����QQ��Ȼ��ʼ���QQִ�У���ȡ������QQ��PID
	KillQQProcess();
	Sleep(2000);
	DWORD QQPid = FindQQParentProcess();

	// �ȴ�QQ����һ��
	Sleep(3000);
	// ���ӵ�������
	if (!AttachDebuggerToProcess(QQPid)) {
		return 1;
	}

	// ��ȡwrapper.node����ַ 
	DWORD_PTR baseAddress = GetModuleBaseAddress(QQPid, _T("wrapper.node"));
	if (baseAddress == 0) {
		return 1;
	}

	// ��ȡ���жϴ����ַ
	DWORD_PTR targetAddress = baseAddress + codeRVA;
	printf("[!] Target virtual address: 0x%p\n", targetAddress);

	HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, QQPid);
	if (hProcess == NULL) {
		printf("[x] Failed to open process. Error: %u\n", GetLastError());
		return 1;
	}

	// ���öϵ�
	if (!SetBreakpoint(hProcess, targetAddress)) {
		CloseHandle(hProcess);
		return 1;
	}

	// �ȴ��жϲ���ȡ
	WaitForBreakpointAndReadPassword(hProcess, targetAddress, QQPid);

	// ��������״̬
	ContinueAndDetach(QQPid);
	system("pause");
	return 0;
}