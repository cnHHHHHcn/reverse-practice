#include <cstdio>
#include <windows.h>
#include <tlhelp32.h>

DWORD GetProcessIDbyName(const wchar_t* ProcessName) {
	PROCESSENTRY32 temp;
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		return 0;
	}
	temp.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hProcessSnap, &temp)) {
		do {
			if (_wcsicmp(temp.szExeFile, ProcessName) == 0) {
				CloseHandle(hProcessSnap);
				return temp.th32ProcessID;
			}
		} while (Process32Next(hProcessSnap, &temp));
	}
	CloseHandle(hProcessSnap);
	return NULL;
}

void* GetModuleBaseAddress(DWORD pid, const wchar_t* Module) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}
	MODULEENTRY32 moduleEntry = { 0 };
	moduleEntry.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hSnapshot, &moduleEntry)) {
		CloseHandle(hSnapshot);
		return 0;
	}
	do {
		if (_wcsicmp(moduleEntry.szModule, Module) == 0 || _wcsicmp(moduleEntry.szExePath, Module) == 0) {
			CloseHandle(hSnapshot);
			return moduleEntry.modBaseAddr;
		}
	} while (Module32Next(hSnapshot, &moduleEntry));

	CloseHandle(hSnapshot);
	return 0;
}


int main() {
	DWORD pid = GetProcessIDbyName(L"notepad.exe");
	void* ProcessBaseAddress = GetModuleBaseAddress(pid, L"notepad.exe");
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

	// 1. 打开进程句柄失败（通常是没加管理员权限，或者进程名写错了）
	if (hProcess == nullptr) {
		printf("[错误] 无法打开目标进程，请确保以管理员身份运行程序！\n");
		return 0;
	}

	void* ProcessHeader = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// 2. 分配本地内存失败（通常是系统内存不足）
	if (ProcessHeader == nullptr) {
		printf("[错误] 本地内存分配失败！\n");
		CloseHandle(hProcess);
		return 0;
	}

	size_t ReadBytes = 0;
	BOOL RTN = ReadProcessMemory(hProcess, ProcessBaseAddress, ProcessHeader, 0x1000, &ReadBytes);

	if (RTN && ReadBytes == 0x1000) {
		for (DWORD i = 0; i < ReadBytes; i += 16) {
			printf("%016llX | ", (uintptr_t)((char*)ProcessBaseAddress + i));
			for (DWORD j = 0; j < 16; j++) {
				unsigned char Byte = *(unsigned char*)((char*)ProcessHeader + i + j);
				printf("%02X ", Byte);
			}
			printf("| ");
			for (DWORD j = 0; j < 16; j++) {
				unsigned char Byte = *(unsigned char*)((char*)ProcessHeader + i + j);
				printf("%c", (Byte >= 32 && Byte <= 126) ? Byte : '.');
			}
			printf("\n");
		}
	}
	else {
		// 3. 读取内存失败（可能是基址不对，或者被反作弊拦截）
		printf("[错误] 内存读取失败！读取字节数: %zu\n", ReadBytes);
	}

	// 4. 正常执行完毕的提示
	printf("\n[完成] 内存读取与打印结束。\n");

	CloseHandle(hProcess);
	VirtualFree(ProcessHeader, 0, MEM_RELEASE);
	return 0;
}
