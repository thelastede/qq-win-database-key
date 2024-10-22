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
PE文件的内存偏移与文件偏移相互转换,不考虑系统为对齐填充偏移转换
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

	if (!bFile2RVA)  // 内存偏移转换为文件偏移  
	{
		//看需要转移的偏移是否在PE头内，如果在则两个偏移相同  
		dwHeaderSize = pNtHeader->OptionalHeader.SizeOfHeaders;
		if (dwAddr <= dwHeaderSize)
		{
			delete lpBase;
			lpBase = NULL;
			return dwAddr;
		}
		else //不再PE头里，查看该地址在哪个区块中  
		{
			for (int i = 0; i < dwSecNum; i++)
			{
				DWORD dwSecSize = pSecHeader[i].Misc.VirtualSize;
				if ((dwAddr >= pSecHeader[i].VirtualAddress) && (dwAddr <= pSecHeader[i].VirtualAddress + dwSecSize))
				{
					//找到该该偏移，则文件偏移 = 该区块的文件偏移 + （该偏移 - 该区块的内存偏移）  
					dwRet = pSecHeader[i].PointerToRawData + dwAddr - pSecHeader[i].VirtualAddress;
				}
			}
		}
	}
	else // 文件偏移转换为内存偏移  
	{
		dwHeaderSize = pNtHeader->OptionalHeader.SizeOfHeaders;
		//看需要转移的偏移是否在PE头内，如果在则两个偏移相同  
		if (dwAddr <= dwHeaderSize)
		{
			delete lpBase;
			lpBase = NULL;
			return dwAddr;
		}
		else//不再PE头里，查看该地址在哪个区块中  
		{
			for (int i = 0; i < dwSecNum; i++)
			{
				DWORD dwSecSize = pSecHeader[i].Misc.VirtualSize;
				if ((dwAddr >= pSecHeader[i].PointerToRawData) && (dwAddr <= pSecHeader[i].PointerToRawData + dwSecSize))
				{
					//找到该该偏移，则内存偏移 = 该区块的内存偏移 + （该偏移 - 该区块的文件偏移）  
					dwRet = pSecHeader[i].VirtualAddress + dwAddr - pSecHeader[i].PointerToRawData;
				}
			}
		}
	}

	//释放内存  
	return dwRet;
}


void GetProcessFilePath(DWORD processID, WCHAR* processFilePath) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

	if (hProcess != NULL) {
		// 获取进程的主模块路径
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

// 遍历进程列表，查找QQ.exe并获取其文件路径
void FindQQProcess(WCHAR* processFilePath) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32;
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (hSnapshot == INVALID_HANDLE_VALUE) {
		_tprintf(TEXT("[x] Failed to take snapshot of processes.\n"));
		return;
	}

	// 遍历进程列表
	if (Process32First(hSnapshot, &pe32)) {
		do {
			if (_tcsicmp(pe32.szExeFile, _T("QQ.exe")) == 0) {
				_tprintf(TEXT("[!] Found QQ.exe with PID: %u\n"), pe32.th32ProcessID);
				GetProcessFilePath(pe32.th32ProcessID, processFilePath);  // 获取QQ.exe的文件路径
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

	// 拼接搜索模式，搜索当前目录下的所有文件和子目录
	_stprintf_s(searchPattern, MAX_PATH, _T("%s\\*"), directory);

	// 查找第一个文件或目录
	hFind = FindFirstFile(searchPattern, &findFileData);
	if (hFind == INVALID_HANDLE_VALUE) {
		_tprintf(_T("[x] Invalid file handle. Error: %u\n"), GetLastError());
		return 0;
	}

	do {
		// 忽略 "." 和 ".." 目录
		if (_tcscmp(findFileData.cFileName, _T(".")) != 0 && _tcscmp(findFileData.cFileName, _T("..")) != 0) {
			// 构造完整的文件路径
			_stprintf_s(fullPath, MAX_PATH, _T("%s\\%s"), directory, findFileData.cFileName);

			// 如果找到的是子目录，递归调用函数
			if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
				if (SearchFiles(fullPath, targetFile) != 0)
					return 1;
			}
			else {
				// 如果是文件，检查文件名是否与目标文件匹配
				if (_tcscmp(findFileData.cFileName, targetFile) == 0) {
					_tprintf(_T("[!] Found target file: %s\n"), fullPath);
					memcpy(targetFileFullPath, fullPath, MAX_PATH);
					return 1;
				}
			}
		}
	} while (FindNextFile(hFind, &findFileData) != 0);

	// 关闭查找句柄
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
	li.QuadPart = 0;  // 偏移量为0，即移动到文件开始
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
		// 创建进程快照
		hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (hSnapshot == INVALID_HANDLE_VALUE) {
			_tprintf(TEXT("[x] Failed to take process snapshot.\n"));
			return 0;
		}

		// 遍历进程列表
		if (Process32First(hSnapshot, &pe32)) {
			do {
				// 检查进程名是否为 QQ.exe
				if (_tcsicmp(pe32.szExeFile, _T("QQ.exe")) == 0) {
					int parentFound = FALSE;
					// 寻找 QQ.exe 主进程
					//_tprintf(TEXT("Found QQ.exe with PID: %d\n"), pe32.th32ProcessID);
					DWORD parentProcessId = pe32.th32ParentProcessID;
					//_tprintf(TEXT("Parent Pid: %d\n"), parentProcessId);

					// 查找父进程名
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

		// 等待一段时间后再次检查
		Sleep(1000); // 每秒检查一次
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
	BYTE int3 = 0xCC; // INT 3 指令
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

	// 检查第 33 个字节是否为 \x00
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
	// 尝试停止调试器附加
	if (!DebugActiveProcessStop(processId)) {
		printf("[x] Failed to detach debugger from process %lu. Error: %lu\n", processId, GetLastError());
		return FALSE;
	}

	printf("[!] Debugger successfully detached from process %lu.\n", processId);
	return TRUE;
}

BOOL SuspendProcess(DWORD processID) {
	// 获取指定进程的快照
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		_tprintf(_T("[x] CreateToolhelp32Snapshot failed: %u\n"), GetLastError());
		return FALSE;
	}

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	// 枚举快照中的线程
	if (Thread32First(hSnapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == processID) {
				// 打开该线程
				HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
				if (hThread == NULL) {
					_tprintf(_T("[x] Failed to open thread: %u\n"), GetLastError());
					CloseHandle(hSnapshot);
					return FALSE;
				}

				// 挂起该线程
				SuspendThread(hThread);
				CloseHandle(hThread);
			}
		} while (Thread32Next(hSnapshot, &threadEntry));
	}

	CloseHandle(hSnapshot);
	return TRUE;
}

BOOL ResumeProcess(DWORD processID) {
	// 获取指定进程的快照
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		_tprintf(_T("[x] CreateToolhelp32Snapshot failed: %u\n"), GetLastError());
		return FALSE;
	}

	THREADENTRY32 threadEntry;
	threadEntry.dwSize = sizeof(THREADENTRY32);

	// 枚举快照中的线程
	if (Thread32First(hSnapshot, &threadEntry)) {
		do {
			if (threadEntry.th32OwnerProcessID == processID) {
				// 打开该线程
				HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadEntry.th32ThreadID);
				if (hThread == NULL) {
					_tprintf(_T("[x] Failed to open thread: %u\n"), GetLastError());
					CloseHandle(hSnapshot);
					return FALSE;
				}

				// 恢复该线程
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

	// 提取密码
	while (TRUE) {
		// 等待调试事件
		if (WaitForDebugEvent(&debugEvent, INFINITE)) {
			// 需要是断点事件
			if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
				debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {

				// 看看地址和下断点的地址对不对得上
				if ((unsigned long long)address != (unsigned long long)debugEvent.u.Exception.ExceptionRecord.ExceptionAddress)
				{
					ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
					continue;
				}

				// 地址对上了，挂起进程避免竞争
				printf("[!] Breakpoint hit at address: 0x%p\n", debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
				SuspendProcess(QQPid);

				HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, debugEvent.dwThreadId);
				if (hThread) {
					// 获取线程上下文
					if (GetThreadContext(hThread, &context)) {
						printf("[*] r8 value: 0x%llx\n", context.R8);
						// 确认密钥是否为想要的格式
						if (ReadProcessMemoryAndCheck(hProcess, (LPCVOID)context.R8))
						{
							// 恢复断点，回退RIP，恢复线程上下文，继续调试，恢复进程
							RestoreBreakpoint(hProcess, address, 0x48);
							context.Rip -= 1;
							SetThreadContext(hThread, &context);
							ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
							CloseHandle(hThread);
							ResumeProcess(QQPid);
							return;
						}
						// 如果密钥格式不对，就在下一条指令下断点，让执行过去，断下来后重新再刚刚的位置下断点，然后让指令继续执行
						else
						{
							// 在下一条指令下断点，并保留被写的字节
							BYTE targetByte = SetBreakpoint(hProcess, (DWORD_PTR)((unsigned long long)address) + 4);
							if (!targetByte) {
								printf("[!] Set breakpoint failed with %d\n", GetLastError());
								CloseHandle(hProcess);
								return;
							}
							// 恢复原目标指令断点，回退RIP，恢复线程上下文，继续调试，恢复进程
							RestoreBreakpoint(hProcess, address, 0x48);
							context.Rip -= 1;
							SetThreadContext(hThread, &context);
							ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
							CloseHandle(hThread);
							ResumeProcess(QQPid);

							// 等到下一个断点断下来
							while (true)
							{
								// 等调试事件
								if (WaitForDebugEvent(&debugEvent, INFINITE)) {
									if (debugEvent.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
										debugEvent.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {

										// 检查地址对不对得上
										if (((unsigned long long)address) + 4 != (unsigned long long)debugEvent.u.Exception.ExceptionRecord.ExceptionAddress)
										{
											printf("[x] Breakpoint hit at address: 0x%p. Not as expected \n", debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
											ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
											continue;
										}

										printf("[!] Breakpoint hit at address: 0x%p.\n", debugEvent.u.Exception.ExceptionRecord.ExceptionAddress);
										// 挂起进程
										SuspendProcess(QQPid);

										// 重新建立线程对象，因为可能是新线程
										HANDLE hhThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, debugEvent.dwThreadId);
										if (hhThread)
										{
											// 重新建立上下文信息，因为可能是新线程
											CONTEXT ccontext;
											ccontext.ContextFlags = CONTEXT_ALL;
											if (GetThreadContext(hhThread, &ccontext))
											{
												// 在目标指令处下断点
												if (!SetBreakpoint(hProcess, address)) {
													printf("[!] Set breakpoint failed with %d\n", GetLastError());
													CloseHandle(hProcess);
													return;
												}
												// 恢复当前断点，恢复RIP，恢复线程上下文，继续调试，恢复进程执行
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
												// 上下文获取失败，继续调试并恢复进程
												printf("[x] Failed to get thread context. Error: %u\n", GetLastError());
												ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
												ResumeProcess(QQPid);
											}

										}
										else
										{
											// 线程打开失败，继续调试并恢复进程
											printf("[x] Failed to open thread. Error: %u\n", GetLastError());
											ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
											ResumeProcess(QQPid);
										}
									}
									else
									{
										// 不是断点事件就等下一个
										ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
										ResumeProcess(QQPid);
									}
								}
							}
						}
					}
					// 上下文获取失败，继续调试并恢复进程
					else {
						printf("[x] Failed to get thread context. Error: %u\n", GetLastError());
						ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
						ResumeProcess(QQPid);
					}
				}
				// 线程打开失败，继续调试并恢复进程
				else
				{
					printf("[x] Failed to open thread. Error: %u\n", GetLastError());
					ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
					ResumeProcess(QQPid);
				}
			}
			// 不是断点事件就等下一个
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

	// 找到目标文件路径并打开 
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

	// 获取目标字符串文件偏移
	fileOffset = FindPatternInFile(targetFileHandle, nt_sqlite3_key_v2_pattern, strlen(nt_sqlite3_key_v2_pattern));
	_tprintf(_T("[!] Found nt_sqlite3_key_v2_pattern offset: %x\n"), fileOffset);

	// 查找目标代码
	codeRVA = findTargetCode(targetFileHandle, fileOffset, codeRVA);
	if (codeRVA == -1)
	{
		_tprintf(_T("[x] Target code not found: \n"));
		return 0;
	}
	CloseHandle(targetFileHandle);
	// 关闭现有QQ，然后开始监控QQ执行，获取父进程QQ的PID
	KillQQProcess();
	Sleep(2000);
	DWORD QQPid = FindQQParentProcess();

	// 等待QQ加载一下
	Sleep(3000);
	// 附加到调试器
	if (!AttachDebuggerToProcess(QQPid)) {
		return 1;
	}

	// 获取wrapper.node基地址 
	DWORD_PTR baseAddress = GetModuleBaseAddress(QQPid, _T("wrapper.node"));
	if (baseAddress == 0) {
		return 1;
	}

	// 获取待中断代码地址
	DWORD_PTR targetAddress = baseAddress + codeRVA;
	printf("[!] Target virtual address: 0x%p\n", targetAddress);

	HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_VM_READ, FALSE, QQPid);
	if (hProcess == NULL) {
		printf("[x] Failed to open process. Error: %u\n", GetLastError());
		return 1;
	}

	// 设置断点
	if (!SetBreakpoint(hProcess, targetAddress)) {
		CloseHandle(hProcess);
		return 1;
	}

	// 等待中断并读取
	WaitForBreakpointAndReadPassword(hProcess, targetAddress, QQPid);

	// 结束调试状态
	ContinueAndDetach(QQPid);
	system("pause");
	return 0;
}