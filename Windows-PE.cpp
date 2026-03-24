// FileTest.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//
#pragma once

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
//#include <ImageHlp.h>

//#pragma comment(lib, "ImageHlp.lib")

uintptr_t GetModuleBaseAddress(DWORD pid, const wchar_t* Module) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		return 0;
	}
	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32);

	if (!Module32First(hSnapshot, &moduleEntry)) {
		CloseHandle(hSnapshot);
		return 0;
	}
	do {
		if (_wcsicmp(moduleEntry.szModule, Module) == 0 || _wcsicmp(moduleEntry.szExePath, Module) == 0) {
			CloseHandle(hSnapshot);
			return (uintptr_t)moduleEntry.modBaseAddr;
		}
	} while (Module32Next(hSnapshot, &moduleEntry));

	CloseHandle(hSnapshot);
	return 0;
}

/*
* 1. RVA 与 FOA 互转 (RVA <-> File Offset)  yes
* 2. 获取导入表 (Import Table)				yes
* 3. 获取导出表 (Export Table)				yes
* 4. 获取资源表 (Resource Table)			
* 5. 手动映射 (Manual Map)
* 6. 重定位表处理 (Relocation Table)		yes
* 7. 校验和计算 (Checksum)					yes
* 8. 获取节区详细信息						pass easy
* 9. 壳检测 (Packers Detection)
*/
namespace PE {
	enum DumpStruct {
		DOS,
		DOS_stub,
		NT,
		SectionTable,
		SectionInfo
	};

	enum ResourceType : WORD {
		Cursor = 1,
		Bitmap = 2,
		Icon = 3,
		Menu = 4,
		Dialog = 5,
		String = 6,
		FontDir = 7,
		Font = 8,
		Accelrator = 9,
		RC_Data = 10,
		MessageTable = 11,
		GroupCursor = Cursor + DIFFERENCE,
		GroupIcon = Icon + DIFFERENCE,
		Version = 16,
		Dlginclude = 17,
	};

	struct FuncInfo {
		WORD Ordinal;
		DWORD RVA_Address;
		char* Name;
	};

	struct ExportInfo {
		char PEName[48];
		DWORD FuncCount;
		DWORD ExportFuncSize;
		FuncInfo* Fn;
	};

	struct ResourceInfo {
		union {
			wchar_t* resName;
			WORD* resID;
		};
		WORD resNameCount;
		WORD resIDCount;
		DWORD resIDOfSize;
	};

	void* Read(const wchar_t* FileName, DWORD& FileSize);
	bool IsValid(void* pBuffer, IMAGE_NT_HEADERS*& out_pNtHeader);
	bool GetMachineType(void* pFileBuffer, WORD& MachineType);
	bool GetSubSystem(void* pFileBuffer, WORD& SubSystemInfo); 
	bool GetEntryPoint(void* pFileBuffer, DWORD& OEP_Address); 
	bool GetPeFormat(void* pFileBuffer, WORD& HDR);
	bool GetSectionName(void* pFileBuffer, void*& out_SectionName, size_t& SectionNameSize);
	bool GetPEChecksum(void* pFileBuffer, DWORD FileSize, DWORD& file_Checksum, DWORD& out_Checksum, bool& out_IsPass);
	bool FileSectionDump(void* pFileBuffer, DumpStruct Signature, char* SectionName, const wchar_t* DumpFile);
	bool MemoryDump(const wchar_t* ExecuteFile, const wchar_t* DumpFile);
	DWORD RvaToFoa(void* pBuffer, DWORD RVA);
	DWORD FoaToRva(void* pBuffer, DWORD FileSize, DWORD FOA);
	bool BuildMemoryImage(void* pFileBuffer, void*& pMemoryImage);
	bool GetExportTable(void* pFileBuffer, ExportInfo*& out_pExpInfo);
	bool FixImportTable(DWORD pid, void* pMemoryImage/*, void* pRemoteImageBase*/);
	bool Relocation(void* pMemoryImage, void* pRemoteImageBase);
	bool SetSectionProperty(void* pFileBuffer, void* pMemoryImage);
	bool SetSectionProperty(HANDLE hProcess, void* pFileBuffer, void* pMemoryImage);
	bool GetResourceTable(void* pFileBuffer, ResourceType TypeID, ResourceInfo& ResInfo);
	// bool MemoryToFileDump(void* pMemoryImage, const wchar_t* DumpFile);
}

void* PE::Read(const wchar_t* FileName, DWORD& FileSize){
	if (FileName == nullptr) return nullptr;
	BOOL RTN = FALSE; void* pFileBuffer = nullptr;
	DWORD ReadTotalBytes = NULL;
	HANDLE hFile = CreateFileW(FileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		LARGE_INTEGER FS;
		RTN = GetFileSizeEx(hFile, &FS);
		FileSize = static_cast<DWORD>(FS.QuadPart);
		if (RTN && FileSize != NULL) {
			pFileBuffer = calloc(1, FileSize);
			if (pFileBuffer != nullptr) {
				RTN = ReadFile(hFile, pFileBuffer, FileSize, &ReadTotalBytes, NULL);
				if (RTN && FileSize == ReadTotalBytes) {
					CloseHandle(hFile);
					return pFileBuffer;
				}
				free(pFileBuffer);
			}
		}
		CloseHandle(hFile);
	}
	return nullptr;
}

bool PE::IsValid(void* pBuffer, IMAGE_NT_HEADERS*& out_pNtHeader) {
	if (pBuffer == nullptr) return false;
	out_pNtHeader = nullptr;
	IMAGE_DOS_HEADER* pDosHeader = static_cast<IMAGE_DOS_HEADER*>(pBuffer);
	if (pDosHeader->e_magic == IMAGE_DOS_SIGNATURE) {
		if (pDosHeader->e_lfanew <= 0 || pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) > 0x7FFFFFFF) return false;
		out_pNtHeader =  reinterpret_cast<IMAGE_NT_HEADERS*>(static_cast<char*>(pBuffer) + pDosHeader->e_lfanew);
		if (static_cast<IMAGE_NT_HEADERS*>(out_pNtHeader)->Signature == IMAGE_NT_SIGNATURE) {
			return true; 
		}
	}
	return false;
}

bool PE::GetMachineType(void* pFileBuffer, WORD& MachineType) {
	if (pFileBuffer == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader)) {
		MachineType = pNtHeader->FileHeader.Machine;
		return true;
	}
	return false;
}

bool PE::GetSubSystem(void* pFileBuffer, WORD& SubSystemInfo) {
	if (pFileBuffer == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader)) {
		SubSystemInfo = pNtHeader->OptionalHeader.Subsystem;
		return true;
	}
	return false;
}

bool PE::GetEntryPoint(void* pFileBuffer, DWORD& OEP_Address) {
	if (pFileBuffer == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader)) {
		OEP_Address = pNtHeader->OptionalHeader.AddressOfEntryPoint;
		return true;
	}
	return false;
}

bool PE::GetPeFormat(void* pFileBuffer, WORD& HDR) {
	if (pFileBuffer == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader)) {
		HDR = pNtHeader->OptionalHeader.Magic;
		return true;
	}
	return false;
}

bool PE::GetSectionName(void* pFileBuffer, void*& out_SectionName, size_t& SectionNameSize) {
	if (pFileBuffer == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	out_SectionName = nullptr;
	if (IsValid(pFileBuffer, pNtHeader)) {
		out_SectionName = calloc(pNtHeader->FileHeader.NumberOfSections, sizeof(char[8]));
		SectionNameSize = pNtHeader->FileHeader.NumberOfSections * sizeof(char[8]);
		IMAGE_SECTION_HEADER* pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
			static_cast<char*>(pFileBuffer) + 
			static_cast<IMAGE_DOS_HEADER*>(pFileBuffer)->e_lfanew +
			offsetof(IMAGE_NT_HEADERS, OptionalHeader) +
			pNtHeader->FileHeader.SizeOfOptionalHeader
		);
		int SectionIndex = 0;
		for (; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			void* WritePos = static_cast<char*>(out_SectionName) + SectionIndex * sizeof(char[8]);
			memcpy(WritePos, pSectionHeader->Name, sizeof(char[8]));
			pSectionHeader++;
		}
		if (SectionIndex == pNtHeader->FileHeader.NumberOfSections) return true;
	}
	return false;
}

bool PE::GetPEChecksum(void* pFileBuffer, DWORD FileSize, DWORD& file_Checksum, DWORD& out_Checksum, bool& out_IsPass) {
	if (pFileBuffer == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	bool RTN = IsValid(pFileBuffer, pNtHeader);
	if (RTN) {
		file_Checksum = pNtHeader->OptionalHeader.CheckSum;
		pNtHeader->OptionalHeader.CheckSum = 0;
		DWORD tmp_FileSize = FileSize + (FileSize % 2);
		DWORD WordBlockTotal = tmp_FileSize / sizeof(WORD);
		out_Checksum = 0;
		for (DWORD WordBlockIndex = 0; WordBlockIndex < WordBlockTotal; WordBlockIndex++) {
			out_Checksum += *(WORD*)((char*)pFileBuffer + WordBlockIndex * sizeof(WORD));
			if (out_Checksum > 0xFFFF) {
				// 再次折叠以防万一
				out_Checksum = (out_Checksum & 0xFFFF) + (out_Checksum >> 16);
				out_Checksum = (out_Checksum & 0xFFFF) + (out_Checksum >> 16);
			}
		}
		out_Checksum += FileSize;
		out_IsPass = (file_Checksum == out_Checksum);
		pNtHeader->OptionalHeader.CheckSum = file_Checksum;
	}
	return RTN;
}

bool PE::FileSectionDump(void* pFileBuffer, DumpStruct Signature, char* SectionName, const wchar_t* DumpFile) {
	if (pFileBuffer == nullptr) return false;
	if (DumpFile == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader;
	if (IsValid(pFileBuffer, pNtHeader)) {
		HANDLE hFile = CreateFileW(DumpFile, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)	return false;
		bool RTN = false;
		void* WritePos = nullptr;
		DWORD DumpSize = 0;
		DWORD WriteBytes = 0;
		DWORD DOS_Offset = static_cast<IMAGE_DOS_HEADER*>(pFileBuffer)->e_lfanew;
		DWORD OPTION_Offset = pNtHeader->FileHeader.SizeOfOptionalHeader;
		switch (Signature) {
		case DOS:
			WritePos = pFileBuffer;
			DumpSize = sizeof(IMAGE_DOS_HEADER);
			break;
		case DOS_stub:
			WritePos = static_cast<char*>(pFileBuffer) + sizeof(IMAGE_DOS_HEADER);
			DumpSize = DOS_Offset - sizeof(IMAGE_DOS_HEADER);
			break;
		case NT:
			WritePos = static_cast<char*>(pFileBuffer) + DOS_Offset;
			DumpSize = offsetof(IMAGE_NT_HEADERS, OptionalHeader) + OPTION_Offset;
			break;
		case SectionTable:
			WritePos = static_cast<char*>(pFileBuffer) + DOS_Offset + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + OPTION_Offset;
			DumpSize = pNtHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
			break;
		case SectionInfo:
			if (SectionName == nullptr) {
				CloseHandle(hFile);
				return false;
			}
			{
				IMAGE_SECTION_HEADER* pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
					static_cast<char*>(pFileBuffer) + DOS_Offset +
					offsetof(IMAGE_NT_HEADERS, OptionalHeader) + OPTION_Offset
				);
				for (int SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
					if (strcmp((char*)pSectionHeader->Name, SectionName) == NULL) {
						WritePos = static_cast<char*>(pFileBuffer) + pSectionHeader->PointerToRawData;
						DumpSize = pSectionHeader->SizeOfRawData;
						break;
					}
					pSectionHeader++;
				}
			}
			break;
		default:
			CloseHandle(hFile);
			return false;
		}
		RTN = WriteFile(hFile, WritePos, DumpSize, &WriteBytes, NULL);
		CloseHandle(hFile);
		if (RTN && DumpSize == WriteBytes) 	return true;
	}
	return false;
}

bool PE::MemoryDump(const wchar_t* ExecuteFile, const wchar_t* DumpFile) {
	STARTUPINFOW si = { 0 }; PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(STARTUPINFOW);
	MODULEINFO ModInfo = { 0 }; SIZE_T ReadBytes = 0;
	void* pMemoryImage = nullptr;
	wchar_t szCommandLine[MAX_PATH * 2] = { 0 };
	wcsncpy_s(szCommandLine, ExecuteFile, sizeof(szCommandLine));
	if (CreateProcessW(NULL, (LPWSTR)szCommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi) && pi.dwProcessId && pi.hProcess) {
		HMODULE BaseAddress = nullptr;
		DWORD Need = NULL;
		EnumProcessModules(pi.hProcess, &BaseAddress, sizeof(BaseAddress), &Need);
		if (BaseAddress) {
			GetModuleInformation(pi.hProcess, BaseAddress, &ModInfo, sizeof(MODULEINFO));
			pMemoryImage = VirtualAlloc(NULL, ModInfo.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (pMemoryImage) {
				if (!ReadProcessMemory(pi.hProcess, ModInfo.lpBaseOfDll, pMemoryImage, ModInfo.SizeOfImage, &ReadBytes) && ReadBytes != ModInfo.SizeOfImage) {
					VirtualFree(pMemoryImage, 0, MEM_RELEASE);
					pMemoryImage = nullptr;
				}
			}
		}
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	if (!pMemoryImage) return false;
	DWORD WriteBytes = 0;
	HANDLE hFile = CreateFileW(DumpFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		WriteFile(hFile, pMemoryImage, ModInfo.SizeOfImage, &WriteBytes, NULL);
		CloseHandle(hFile);
	}
	return true;
}

DWORD PE::RvaToFoa(void* pBuffer, DWORD RVA) {
	if (pBuffer == nullptr) return -1;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pBuffer, pNtHeader)) {
		if (RVA > pNtHeader->OptionalHeader.SizeOfImage) return -1;
		if (RVA < pNtHeader->OptionalHeader.SizeOfHeaders) return RVA;
		IMAGE_SECTION_HEADER* pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
			(char*)pNtHeader + sizeof(pNtHeader->Signature) + 
			sizeof(IMAGE_FILE_HEADER) + pNtHeader->FileHeader.SizeOfOptionalHeader
			);
		for (DWORD SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			DWORD VAStart = pSectionHeader->VirtualAddress;
			DWORD VAEnd = pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize;
			if (VAStart <= RVA && RVA <= VAEnd) {
				DWORD RVA_Offset = RVA - VAStart;
				return pSectionHeader->PointerToRawData + RVA_Offset;
			}
			pSectionHeader++;
		}
	}
	return -1;
}

DWORD PE::FoaToRva(void* pBuffer, DWORD FileSize, DWORD FOA) {
	if (pBuffer == nullptr) return -1;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pBuffer, pNtHeader)) {
		if (FOA > FileSize) return -1;
		if (FOA < pNtHeader->OptionalHeader.SizeOfHeaders) return FOA;
		IMAGE_SECTION_HEADER* pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
			(char*)pNtHeader + sizeof(pNtHeader->Signature) + 
			sizeof(IMAGE_FILE_HEADER) +	pNtHeader->FileHeader.SizeOfOptionalHeader
			);
		for (DWORD SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			DWORD FAStart = pSectionHeader->PointerToRawData;
			DWORD FAEnd = pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData;
			if (FAStart <= FOA && FOA <= FAEnd) {
				DWORD FOA_Offset = FOA - pSectionHeader->PointerToRawData;
				return pSectionHeader->VirtualAddress + FOA_Offset;
			}
			pSectionHeader++;
		}
	}
	return -1;
}

/**
 * @brief 构建内存中的 PE 镜像
 * 将磁盘上的 PE 文件（通常未对齐或按文件对齐）复制并重组为内存对齐格式。
 *
 * @param pFileBuffer 指向磁盘上原始 PE 文件数据的指针
 * @param pMemoryImage [输出] 指向新分配的、已重组的内存镜像基址
 * @return bool 成功返回 true，失败返回 false
 */
bool PE::BuildMemoryImage(void* pFileBuffer, void*& pMemoryImage) {
	if (pFileBuffer == nullptr) return false;

	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	// 验证文件头有效性并获取 NT 头指针
	if (IsValid(pFileBuffer, pNtHeader)) {
		void* Base = nullptr;
		// 1. 分配内存：大小为 OptionalHeader 中定义的 SizeOfImage (内存对齐后的总大小)
		// 权限设为 PAGE_READWRITE 以便后续写入数据和修复重定位/导入表
		Base = VirtualAlloc(NULL, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_READWRITE);
		if (Base == nullptr) return false;

		// 2. 复制 PE 头 (DOS 头 + NT 头 + 节表)
		// 复制大小为 SizeOfHeaders，这通常包含了所有头部信息和节表
		memcpy(Base, pFileBuffer, pNtHeader->OptionalHeader.SizeOfHeaders);

		void* WritePos = nullptr; // 目标内存中的写入位置
		void* resPos = nullptr;   // 源文件缓冲区中的读取位置
		size_t WriteSize = 0;     // 实际要复制的数据大小

		// 3. 获取节表 (Section Header) 的起始位置
		// 计算公式：NT头指针 + Signature(4字节) + FileHeader + OptionalHeader大小
		IMAGE_SECTION_HEADER* pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
			(char*)pNtHeader + sizeof(pNtHeader->Signature) +
			sizeof(IMAGE_FILE_HEADER) + pNtHeader->FileHeader.SizeOfOptionalHeader
		);

		// 4. 遍历所有节区，将数据从文件偏移位置复制到内存虚拟地址位置
		for (int SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			// 目标地址 = 基址 + 节的虚拟地址 (VirtualAddress)
			WritePos = static_cast<void*>(static_cast<char*>(Base) + pSectionHeader->VirtualAddress);

			// 源地址 = 文件缓冲基址 + 节的文件偏移 (PointerToRawData)
			resPos = static_cast<void*>(static_cast<char*>(pFileBuffer) + pSectionHeader->PointerToRawData);

			// 复制大小：取 "内存中所需大小 (VirtualSize)" 和 "文件中实际大小 (SizeOfRawData)" 的较小值
			// 防止越界读取文件或写入超出预期内存
			WriteSize = min(pSectionHeader->Misc.VirtualSize, pSectionHeader->SizeOfRawData);

			memcpy(WritePos, resPos, WriteSize);

			// 移动到下一个节表项
			pSectionHeader++;
		}

		pMemoryImage = Base;
		return true;
	}
	return false;
}

bool PE::GetExportTable(void* pFileBuffer, ExportInfo*& out_pExpInfo) {
	if (pFileBuffer == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader)) {
		DWORD FileOffset = 0;
		IMAGE_DATA_DIRECTORY DataDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		out_pExpInfo = static_cast<ExportInfo*>(calloc(1, sizeof(ExportInfo)));
		if (out_pExpInfo == nullptr) return false;
		if (DataDir.VirtualAddress == 0 || DataDir.Size == 0) {
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return false;
		}
		FileOffset = RvaToFoa(pFileBuffer, DataDir.VirtualAddress);
		if (FileOffset == DWORD(-1)) {
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return false;
		}
		IMAGE_EXPORT_DIRECTORY* pExportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
			static_cast<char*>(pFileBuffer) + FileOffset
			);
		// 获取 PE 文件名称 
		FileOffset = RvaToFoa(pFileBuffer, pExportDir->Name);
		if (FileOffset == DWORD(-1)) {
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return false;
		}
		char* FileName = static_cast<char*>(pFileBuffer) + FileOffset;
		strcpy_s(out_pExpInfo->PEName, FileName);
		out_pExpInfo->ExportFuncSize = 0;

		// 默认给一个 FuncInfo结构体空间
		FuncInfo* pFunctionsInfo = static_cast<FuncInfo*>(calloc(1, sizeof(FuncInfo)));
		if (pFunctionsInfo == nullptr) {
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return false;
		}
		int RealFunctions = 0;
		DWORD FuncIndex = 0;

		// 指向 函数地址RVA
		FileOffset = RvaToFoa(pFileBuffer, pExportDir->AddressOfFunctions);
		if (FileOffset == DWORD(-1)) {
			free(out_pExpInfo->Fn);
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return false;
		}
		DWORD* pFuncAddr = reinterpret_cast<DWORD*>(
			static_cast<char*>(pFileBuffer) + FileOffset
			);
		// 指向 函数序号 
		FileOffset = RvaToFoa(pFileBuffer, pExportDir->AddressOfNameOrdinals);
		if (FileOffset == DWORD(-1)) {
			free(out_pExpInfo->Fn);
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return false;
		}
		WORD* pFuncOrdinals = reinterpret_cast<WORD*>(
			static_cast<char*>(pFileBuffer) + FileOffset
			);
		// 指向 函数名称RVA
		FileOffset = RvaToFoa(pFileBuffer, pExportDir->AddressOfNames);
		if (FileOffset == DWORD(-1)) {
			free(out_pExpInfo->Fn);
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return false;
		}
		DWORD* FuncNameOffset = reinterpret_cast<DWORD*>(
			static_cast<char*>(pFileBuffer) + FileOffset
			);

		for (FuncIndex = (pExportDir->Base - 1); FuncIndex < pExportDir->NumberOfFunctions; FuncIndex++) {

			// 如果 函数地址RVA 值为 NULL，证明没有函数
			if (pFuncAddr[FuncIndex] == NULL) continue;
			// 给 FuncInfo结构体 动态扩容空间
			if (RealFunctions > 0) {
				void* tmp_Pointer = realloc(pFunctionsInfo, sizeof(FuncInfo) * (RealFunctions + 1));
				if (tmp_Pointer == nullptr) {
					free(out_pExpInfo);
					out_pExpInfo = nullptr;
					return false;
				}
				pFunctionsInfo = static_cast<FuncInfo*>(tmp_Pointer);
			}
			FuncInfo* pCurrentFunctionsInfo = reinterpret_cast<FuncInfo*>(
				(char*)pFunctionsInfo + sizeof(FuncInfo) * RealFunctions
				);
			// 填入 函数地址RVA 和 序号
			pCurrentFunctionsInfo->RVA_Address = pFuncAddr[FuncIndex];
			pCurrentFunctionsInfo->Ordinal = pFuncOrdinals[FuncIndex];
			// 当前指向为 函数名RVA 块(4 bytes), 需要再进行一次 RvaToFoa
			FileOffset = RvaToFoa(pFileBuffer, FuncNameOffset[FuncIndex]);
			if (FileOffset == DWORD(-1)) {
				free(out_pExpInfo->Fn);
				free(out_pExpInfo);
				out_pExpInfo = nullptr;
				return false;
			}
			// 修正之后传入 函数名称 指针
			pCurrentFunctionsInfo->Name = static_cast<char*>(static_cast<char*>(pFileBuffer) + FileOffset);

			RealFunctions++;
		}
		out_pExpInfo->Fn = pFunctionsInfo;
		out_pExpInfo->FuncCount = RealFunctions;
		out_pExpInfo->ExportFuncSize = sizeof(FuncInfo) * RealFunctions;
		return (pExportDir->NumberOfFunctions == FuncIndex);
	}
	return false;
}

/**
 * @brief 修复导入表 (针对远程进程)
 * 解析本地镜像的导入表，加载对应的 DLL，获取函数在**本地进程**中的偏移，
 * 然后计算出该函数在**远程进程** (pid) 中的绝对地址，并填入 IAT。
 *
 * @param pid 目标远程进程的 ID
 * @param pMemoryImage 本地已构建好的 PE 内存镜像
 * @param pRemoteImageBase 该镜像在远程进程中的预期基址 (用于计算最终绝对地址)
 * @return bool 成功返回 true，失败返回 false
 */
bool PE::FixImportTable(DWORD pid, void* pMemoryImage /*, void* pRemoteImageBase*/) {
	if (pid == 0) return false;
	if (pMemoryImage == nullptr) return false;
	//if (pRemoteImageBase == nullptr) return false;

	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pMemoryImage, pNtHeader)) {

		// 获取导入表目录项
		IMAGE_DATA_DIRECTORY DataDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (DataDir.VirtualAddress == 0 || DataDir.Size == 0) return true; // 无导入表，视为成功

		// 定位到导入描述符数组
		IMAGE_IMPORT_DESCRIPTOR* pImportDest = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
			static_cast<char*>(pMemoryImage) + DataDir.VirtualAddress
		);

		// 遍历每个导入的 DLL (以 Name 为 0 结尾)
		while (pImportDest->Name) {
			// 获取依赖的 DLL 名称 (如 "kernel32.dll")
			char* pDllName = static_cast<char*>(static_cast<char*>(pMemoryImage) + pImportDest->Name);

			// OriginalFirstThunk: 指向导入名称表 (INT)，包含原始函数名/序号
			IMAGE_THUNK_DATA* pOriginalThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
				static_cast<char*>(pMemoryImage) + pImportDest->OriginalFirstThunk
			);

			// FirstThunk: 指向导入地址表 (IAT)，我们需要在这里填入最终的函数地址
			IMAGE_THUNK_DATA* pThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
				static_cast<char*>(pMemoryImage) + pImportDest->FirstThunk
			);

			LPVOID FnAddr = nullptr; // 用于存储本地进程中获取到的函数地址

			// 1. 在本地进程加载该 DLL，以便获取函数地址
			HMODULE local_hModule = LoadLibraryA(pDllName);
			if (local_hModule == nullptr) return false;

			// 转换 DLL 名为宽字符，用于查询远程进程中的模块基址
			WCHAR wDllName[MAX_PATH] = { 0 };
			MultiByteToWideChar(CP_ACP, 0, pDllName, -1, wDllName, MAX_PATH);

			// 2. 获取该 DLL 在**远程进程**中的基址
			// 假设远程进程已经加载了该 DLL，且版本与本地一致（否则偏移可能无效）
			HMODULE remote_hModule = (HMODULE)GetModuleBaseAddress(pid, wDllName);
			if (remote_hModule == nullptr) {
				FreeLibrary(local_hModule);
				return false;
			}

			// 遍历该 DLL 导入的所有函数
			while (pOriginalThunk->u1.AddressOfData != 0) {
				// 判断是按序号导入还是按名称导入
				if (pOriginalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
					// 按序号导入
					WORD Ordinal = IMAGE_ORDINAL(pOriginalThunk->u1.Ordinal);
					FnAddr = GetProcAddress(local_hModule, (LPCSTR)Ordinal);
				}
				else {
					// 按名称导入
					// 获取函数名称结构体
					IMAGE_IMPORT_BY_NAME* pImportFuncName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(
						static_cast<char*>(pMemoryImage) + pOriginalThunk->u1.AddressOfData
					);
					FnAddr = GetProcAddress(local_hModule, pImportFuncName->Name);
				}

				// [安全性/正确性检查]
				// 确保获取到的函数地址确实位于刚才 LoadLibrary 加载的模块范围内
				MODULEINFO ModuleInfo = { 0 };
				if (!GetModuleInformation(GetCurrentProcess(), local_hModule, &ModuleInfo, sizeof(MODULEINFO))) {
					FreeLibrary(local_hModule);
					return false;
				}

				ULONG_PTR ModuleStart = (ULONG_PTR)local_hModule;
				ULONG_PTR ModuleEnd = (ULONG_PTR)local_hModule + ModuleInfo.SizeOfImage;
				ULONG_PTR ModuleFnAddr = (ULONG_PTR)FnAddr;

				// 如果函数地址不在模块范围内，说明出错
				if (ModuleFnAddr <= ModuleStart || ModuleFnAddr >= ModuleEnd) {
					FreeLibrary(local_hModule);
					return false;
				}

				// 3. 计算函数相对于模块基址的偏移 (RVA)
				ULONG_PTR FnAddrOffset = (ULONG_PTR)FnAddr - (ULONG_PTR)local_hModule;

				// 4. 计算该函数在远程进程中的绝对地址
				// 公式：远程模块基址 + 函数偏移
				// 并将结果写入到本地镜像的 IAT (pThunk) 中
				// 当这个本地镜像被写入远程进程后，远程进程执行时就会跳转到正确的远程函数地址
				pThunk->u1.Function = (ULONG_PTR)remote_hModule + FnAddrOffset;

				pOriginalThunk++;
				pThunk++;
			}

			// 释放本地加载的 DLL，因为我们只需要它的地址信息，不需要它在本地长期驻留
			FreeLibrary(local_hModule);
			pImportDest++;
		}
		return true;
	}
	return false;
}

bool PE::Relocation(void* pMemoryImage, void* pRemoteImage) {
	if (pMemoryImage == nullptr) return false;
	if (pRemoteImage == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pMemoryImage, pNtHeader)) {
		IMAGE_DATA_DIRECTORY DataDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (DataDir.VirtualAddress == 0 || DataDir.Size == 0) return true;
		IMAGE_BASE_RELOCATION* pBaseReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
			static_cast<char*>(pMemoryImage) + DataDir.VirtualAddress
		);
		ULONG_PTR Delta = (ULONG_PTR)pRemoteImage - (ULONG_PTR)pMemoryImage;
		if (Delta == 0) return true;
		while (pBaseReloc->VirtualAddress) {
			WORD RelocCount = static_cast<WORD>((pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD));
			WORD* pRelocBlock = reinterpret_cast<WORD*>((char*)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));
			for (DWORD RelocIndex = 0; RelocIndex < RelocCount; RelocIndex++) {
				WORD RelocType = pRelocBlock[RelocIndex] >> 12;
				WORD RelocOffset = pRelocBlock[RelocIndex] & 0x0FFF;
				if (RelocType == IMAGE_REL_BASED_HIGHLOW || RelocType == IMAGE_REL_BASED_DIR64) {
					ULONG_PTR* pRelocAddr = reinterpret_cast<ULONG_PTR*>(
						static_cast<char*>(pMemoryImage) + pBaseReloc->VirtualAddress + RelocOffset
					);
					*pRelocAddr += Delta;
				}
			}
			pBaseReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
				(char*)pBaseReloc + pBaseReloc->SizeOfBlock
			);
		}
		return true;
	}
	return false;
}


bool PE::SetSectionProperty(void* pFileBuffer, void* pMemoryImage) {
	if (pFileBuffer == nullptr) return false;
	if (pMemoryImage == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader)) {
		IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
		for (int SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			// 根据节区特征确定保护属性
			DWORD memProperty = PAGE_READONLY;
			if (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE)			{
				memProperty = (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
			}else if (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE){
				memProperty = PAGE_READWRITE;
			}
			void* pSectionAddr = (char*)pMemoryImage + pSectionHeader[SectionIndex].VirtualAddress;
			DWORD oldmemProperty = 0;
			VirtualProtect(pSectionAddr, pSectionHeader[SectionIndex].Misc.VirtualSize, memProperty, &oldmemProperty);
			pSectionHeader++;
		}
		return true;
	}
	return false;
}

bool PE::SetSectionProperty(HANDLE hProcess, void* pFileBuffer, void* pMemoryImage) {
	if (pFileBuffer == nullptr) return false;
	if (pMemoryImage == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader)) {
		IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
		for (int SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			// 根据节区特征确定保护属性
			DWORD memProperty = PAGE_READONLY;
			if (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				memProperty = (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
			}
			else if (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE) {
				memProperty = PAGE_READWRITE;
			}
			void* pSectionAddr = (char*)pMemoryImage + pSectionHeader[SectionIndex].VirtualAddress;
			DWORD oldmemProperty = 0;
			VirtualProtectEx(hProcess, pSectionAddr, pSectionHeader[SectionIndex].Misc.VirtualSize, memProperty, &oldmemProperty);
			pSectionHeader++;
		}
		return true;
	}
	return false;
}

bool PE::GetResourceTable(void* pFileBuffer, PE::ResourceType TypeID, PE::ResourceInfo& ResInfo) {
	if (pFileBuffer == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader)) {
		IMAGE_DATA_DIRECTORY DataDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];
		if (DataDir.VirtualAddress == 0 || DataDir.Size == 0) return false;
		DWORD FileOffset = RvaToFoa(pFileBuffer, DataDir.VirtualAddress);
		if (FileOffset == DWORD(-1)) return false;
		IMAGE_RESOURCE_DIRECTORY* pResource = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY*>(
			static_cast<char*>(pFileBuffer) + FileOffset
		);
		ResInfo.resNameCount = pResource->NumberOfNamedEntries;
		ResInfo.resIDCount = pResource->NumberOfIdEntries;
		DWORD ResourceCount = pResource->NumberOfIdEntries + pResource->NumberOfNamedEntries;
		IMAGE_RESOURCE_DIRECTORY_ENTRY* pResourceDir = reinterpret_cast<IMAGE_RESOURCE_DIRECTORY_ENTRY*>(
			static_cast<char*>(pFileBuffer) + FileOffset + sizeof(IMAGE_RESOURCE_DIRECTORY)
		);
		ResInfo.resIDOfSize = ResourceCount * sizeof(void*);
		void* pRes = calloc(ResourceCount, sizeof(void*));
		if (pRes == nullptr) return false;
		ResInfo.resName = static_cast<wchar_t*>(pRes);
		for (DWORD resIndex = 0; resIndex < ResourceCount; resIndex++) {
			if (pResourceDir->NameIsString) {
				FileOffset = RvaToFoa(pFileBuffer, pResourceDir->NameOffset);
				void* pData = static_cast<void*>(reinterpret_cast<char*>(pResource) + FileOffset);
				memcpy(pRes, pData, sizeof(wchar_t*));
			}else {
				memcpy(pRes, &pResourceDir->Id, sizeof(WORD));
			}
			pRes = static_cast<char*>(pRes) + sizeof(void*);
			pResourceDir++;
		}
	}
	return false;
}
/*
* 本意是想通过内存的数据还原成一个文件，失败
bool PE::MemoryToFileDump(void* pMemoryImage, const wchar_t* DumpFile)
{
	if (pMemoryImage == nullptr) return false;
	if (DumpFile == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pMemoryImage, pNtHeader)) {
		DWORD FileAlignment = pNtHeader->OptionalHeader.FileAlignment, WriteBytes = 0;
		DWORD WriteSize = (pNtHeader->OptionalHeader.SizeOfHeaders + FileAlignment - 1) & ~(FileAlignment - 1);
		HANDLE hFile = CreateFileW(DumpFile, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)	return false;

		bool RTN = WriteFile(hFile, pMemoryImage, WriteSize, &WriteBytes, NULL);
		if (!RTN && WriteBytes != FileAlignment) {
			CloseHandle(hFile);
			return false;
		}
		IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
		for (int SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			void* WritePos = static_cast<void*>(
				static_cast<char*>(pMemoryImage) + pSectionHeader->VirtualAddress
			);
			//WriteSize = (pSectionHeader->Misc.VirtualSize + FileAlignment - 1) & ~(FileAlignment - 1); // 标准向上对齐
			WriteSize = pSectionHeader->SizeOfRawData;
			RTN = WriteFile(hFile, WritePos, WriteSize, &WriteBytes, NULL);
			if (!RTN && WriteBytes != WriteSize) {
				CloseHandle(hFile);
				return false;
			}
			pSectionHeader++;
		}
		IMAGE_DATA_DIRECTORY DataDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		if (DataDir.VirtualAddress != 0 && DataDir.Size != 0) {
			IMAGE_IMPORT_DESCRIPTOR* pImportDest = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
				static_cast<char*>(pMemoryImage) + DataDir.VirtualAddress
				);

			while (pImportDest->Name != 0) { // 判断模块名是否为空来结束循环，比判断 OriginalFirstThunk 更稳妥
				DWORD originalThunkRVA = pImportDest->OriginalFirstThunk;
				DWORD firstThunkRVA = pImportDest->FirstThunk;

				// 情况 1: INT (OriginalFirstThunk) 存在
				if (originalThunkRVA != 0) {
					IMAGE_THUNK_DATA* pOriginalThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
						static_cast<char*>(pMemoryImage) + originalThunkRVA
						);
					IMAGE_THUNK_DATA* pThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(
						static_cast<char*>(pMemoryImage) + firstThunkRVA
						);

					// 遍历直到遇到全 0 的项
					while (pOriginalThunk->u1.AddressOfData != 0) {
						// 【关键修正】：
						// 在生成的文件中，IAT (pThunk) 应该存储指向函数名的 RVA。
						// 而 pOriginalThunk->u1.AddressOfData 本身就是这个 RVA。
						// 所以，我们要确保 pThunk 里存的也是这个 RVA，而不是内存绝对地址。

						// 如果当前 pThunk 里存的是绝对地址（内存状态），我们需要把它改回 RVA
						pThunk->u1.AddressOfData = pOriginalThunk->u1.AddressOfData;

						pOriginalThunk++;
						pThunk++;
					}
				}
				// 情况 2: INT 为 0，只能依赖 IAT (但这在内存 Dump 中通常意味着数据已损坏/扁平化)
				else {
					// 如果 OriginalFirstThunk 是 0，说明没有名字表。
					// 此时 FirstThunk 里通常是绝对地址。
					// 【无法自动修复】：你无法从绝对地址 0x77001234 反推出 "MessageBoxA"。
					// 这种情况下，必须使用高级工具（如 Scyller）进行 IAT 扫描修复，手动代码很难搞定。
					// 这里只能标记为需要人工介入，或者尝试跳过（会导致运行崩溃）。

					// TODO: 这里的逻辑非常复杂，通常需要：
					// 1. 遍历 IAT 中的每个地址。
					// 2. 判断该地址属于哪个已加载的 DLL。
					// 3. 计算偏移，查找导出表匹配函数名。
					// 4. 在文件中新建一个 INT 区域，填入名字。
					// 5. 更新 ImportDescriptor 指向新的 INT。
					// 6. 将 IAT 清零或填入新 INT 的 RVA。

					break; // 暂时跳出，避免死循环或错误写入
				}

				pImportDest++;
			}
		}
		return true;
	}
	return false;
}
*/

int main(){
	
	DWORD FileSize = 0;
	void* pFile = PE::Read(L"C:\\Users\\OMEN\\Desktop\\KernelBase.dll", FileSize);
	PE::ResourceInfo Res = { 0 };
	PE::GetResourceTable(pFile, PE::Icon , Res);

	/*
	DWORD FileSize = 0;
	void* pFile = PE::Read(L"C:\\Users\\OMEN\\Desktop\\KernelBase.dll", FileSize);
	PE::ExportInfo* pExp = nullptr;
	PE::GetExportTable(pFile, pExp);
	for (int i = 0; i < pExp->ExportFuncSize / sizeof(PE::FuncInfo); i++) {
		PE::FuncInfo* pCurrent = (PE::FuncInfo*)((char*)pExp->Fn + sizeof(PE::FuncInfo) * i);
		std::cout  << pCurrent->Ordinal << "\t\t" <<  pCurrent->RVA_Address << "\t\t" <<  pCurrent->Name << "\r\n";
	}
	*/
	
	/*
	PE::MemoryDump(L"C:\\Users\\OMEN\\Desktop\\1.exe", L"C:\\Users\\OMEN\\Desktop\\1.txt");
	*/

	/*
	DWORD FileSum = 0, CheckSum = 0;
	//MapFileAndCheckSumW(L"C:\\Users\\OMEN\\Desktop\\test1.exe", &FileSum, &CheckSum);
	DWORD FileSize = 0; bool RTN = false;
	void* pFile = PE::Read(L"C:\\Users\\OMEN\\Desktop\\test1.exe", FileSize);
	PE::GetPEChecksum(pFile, FileSize, FileSum, CheckSum, RTN);
	*/

	/*
	DWORD FileSize = 0;
	void* pFile = PE::Read(L"C:\\Users\\OMEN\\Desktop\\MFCLibpvzCheat64.dll", FileSize);
	void* pSectionName = nullptr;
	size_t SectionNameSize = 0;
	PE::DumpStructData(pFile, PE::DOS, nullptr, L"D:\\MFCLibpvzCheat64-DOS.txt");
	PE::DumpStructData(pFile, PE::DOS_stub, nullptr, L"D:\\MFCLibpvzCheat64-DOS_stub.txt");
	PE::DumpStructData(pFile, PE::NT, nullptr, L"D:\\MFCLibpvzCheat64-NT.txt");
	PE::DumpStructData(pFile, PE::SectionTable, nullptr, L"D:\\MFCLibpvzCheat64-SectionTable.txt");
	if (PE::GetSectionName(pFile, pSectionName, SectionNameSize)) {
		for (int Index = 0; Index < SectionNameSize / sizeof(char[8]); Index++) {
			std::cout << (char*)pSectionName + Index * sizeof(char[8]) << "\n";
			std::wstring out_File = L"D:\\MFCLibpvzCheat64-Section";
			out_File.append(1, 49 + Index);
			out_File.append(L".txt");
			PE::DumpStructData(pFile, PE::SectionInfo, (char*)pSectionName + Index * sizeof(char[8]), out_File.c_str());
		}
	}
	*/
}

