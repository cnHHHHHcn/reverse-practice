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

/*
* 
* 调用 Read，GetSectionName, GetExportTable，GetResourceTable 这些方法之后一定要记得调用 free(pointer);
* 调用 BuildMemoryImage 方法之后一定要调用 VirtualFree(pointer, 0, MEM_RELEASE);
* 否则会发生内存泄露
* 
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

	void* Read(const wchar_t* FileName, DWORD& out_FileSize);
	bool IsValid(void* pBuffer, IMAGE_NT_HEADERS*& out_pNtHeader);
	bool GetMachineType(void* pFileBuffer, WORD& out_MachineType);
	bool GetSubSystem(void* pFileBuffer, WORD& out_SubSystemInfo);
	bool GetEntryPoint(void* pFileBuffer, DWORD& out_OEP_Address);
	bool GetPeFormat(void* pFileBuffer, WORD& out_HDR);
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

/**
 * @brief 读取整个文件内容到内存缓冲区
 *
 * @param FileName [in] 要读取的文件路径 (宽字符字符串)
 * @param out_FileSize [out] 输出参数，返回读取到的文件大小 (字节)
 * @return void* 成功返回指向文件内容的指针 (需手动 free)，失败返回 nullptr
 */
void* PE::Read(const wchar_t* FileName, DWORD& out_FileSize){
	if (FileName == nullptr) return nullptr;
	BOOL RTN = FALSE; void* pFileBuffer = nullptr;
	DWORD ReadTotalBytes = NULL;
	HANDLE hFile = CreateFileW(FileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE) {
		LARGE_INTEGER FS;
		RTN = GetFileSizeEx(hFile, &FS);
		out_FileSize = static_cast<DWORD>(FS.QuadPart);
		if (RTN && out_FileSize != NULL) {
			pFileBuffer = calloc(1, out_FileSize);
			if (pFileBuffer != nullptr) {
				RTN = ReadFile(hFile, pFileBuffer, out_FileSize, &ReadTotalBytes, NULL);
				if (RTN && out_FileSize == ReadTotalBytes) {
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

/**
 * @brief 验证内存缓冲区是否为有效的 PE 文件
 *
 * @param pBuffer [in] 指向文件内存缓冲区的指针
 * @param out_pNtHeader [out] 输出参数，如果验证成功，指向 IMAGE_NT_HEADERS 结构
 * @return bool 验证成功返回 true，否则返回 false
 */
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

/**
 * @brief 获取 PE 文件的机器类型 (如 x86, x64, ARM 等)
 *
 * @param pFileBuffer [in] 文件内存缓冲区
 * @param out_MachineType [out] 输出机器类型 (例如: IMAGE_FILE_MACHINE_AMD64)
 * @return bool 成功返回 true
 */
bool PE::GetMachineType(void* pFileBuffer, WORD& out_MachineType) {
	if (pFileBuffer == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader)) {
		out_MachineType = pNtHeader->FileHeader.Machine;
		return true;
	}
	return false;
}

/**
 * @brief 获取 PE 文件的子系统类型 (如 GUI, Console, Driver 等)
 *
 * @param pFileBuffer [in] 文件内存缓冲区
 * @param out_SubSystemInfo [out] 输出子系统类型 (例如: IMAGE_SUBSYSTEM_WINDOWS_GUI)
 * @return bool 成功返回 true
 */
bool PE::GetSubSystem(void* pFileBuffer, WORD& out_SubSystemInfo) {
	if (pFileBuffer == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader)) {
		out_SubSystemInfo = pNtHeader->OptionalHeader.Subsystem;
		return true;
	}
	return false;
}

/**
 * @brief 获取 PE 文件的入口点地址 (OEP - Original Entry Point)
 *
 * @param pFileBuffer [in] 文件内存缓冲区
 * @param out_OEP_Address [out] 输出入口点相对虚拟地址 (RVA)
 * @return bool 成功返回 true
 */
bool PE::GetEntryPoint(void* pFileBuffer, DWORD& out_OEP_Address) {
	if (pFileBuffer == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader)) {
		out_OEP_Address = pNtHeader->OptionalHeader.AddressOfEntryPoint;
		return true;
	}
	return false;
}

/**
 * @brief 获取 PE 文件的格式 (PE32 或 PE32+)
 *
 * @param pFileBuffer [in] 文件内存缓冲区
 * @param out_HDR [out] 输出 Magic 值 (IMAGE_NT_OPTIONAL_HDR32_MAGIC 或 IMAGE_NT_OPTIONAL_HDR64_MAGIC)
 * @return bool 成功返回 true
 */
bool PE::GetPeFormat(void* pFileBuffer, WORD& out_HDR) {
	if (pFileBuffer == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader)) {
		out_HDR = pNtHeader->OptionalHeader.Magic;
		return true;
	}
	return false;
}

/**
 * @brief 获取所有节的名称 (Section Names)
 *
 * @param pFileBuffer [in] PE 文件内存缓冲区
 * @param out_SectionName [out] 输出参数，指向包含所有节名的连续内存块 (需调用者 free)
 *                             每个节名固定为 8 字节 (char[8])
 * @param SectionNameSize [out] 输出参数，返回分配的总字节数
 * @return bool 成功返回 true，失败返回 false
 */
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

/**
 * @brief 计算并验证 PE 文件的校验和 (Checksum)
 *
 * @param pFileBuffer [in] PE 文件内存缓冲区
 * @param FileSize [in] 文件总大小
 * @param file_Checksum [out] 输出文件中原本存储的校验和值
 * @param out_Checksum [out] 输出重新计算得到的校验和值
 * @param out_IsPass [out] 输出校验结果 (两者是否相等)
 * @return bool 如果文件是有效的 PE 则返回 true，否则 false
 */
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

// 定义用于参数 Signature 的开关枚举
// enum DumpStruct { DOS, DOS_stub, NT, SectionTable, SectionInfo };

/**
 * @brief 将 PE 文件的特定部分转储到磁盘文件
 *
 * @param pFileBuffer [in] PE 文件内存缓冲区
 * @param Signature [in] 指定要转储的部分 (DOS头, Stub, NT头, 节表, 或特定节区内容)
 * @param SectionName [in] 当 Signature 为 SectionInfo 时，指定具体的节名称 (如 ".text")
 * @param DumpFile [in] 输出文件的路径
 * @return bool 成功返回 true
 */
bool PE::FileSectionDump(void* pFileBuffer, DumpStruct Signature, char* SectionName, const wchar_t* DumpFile) {
	if (pFileBuffer == nullptr) return false;
	if (DumpFile == nullptr) return false;

	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader)) {
		// 创建输出文件
		HANDLE hFile = CreateFileW(DumpFile, GENERIC_WRITE, NULL, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (hFile == INVALID_HANDLE_VALUE)	return false;

		bool RTN = false;
		void* WritePos = nullptr; // 数据源指针
		DWORD DumpSize = 0;       // 数据大小
		DWORD WriteBytes = 0;     // 实际写入字节数

		// 预计算关键偏移量
		DWORD DOS_Offset = static_cast<IMAGE_DOS_HEADER*>(pFileBuffer)->e_lfanew;
		DWORD OPTION_Offset = pNtHeader->FileHeader.SizeOfOptionalHeader;

		switch (Signature) {
		case DOS:
			// 转储 DOS 头 (通常是前 64 字节)
			WritePos = pFileBuffer;
			DumpSize = sizeof(IMAGE_DOS_HEADER);
			break;

		case DOS_stub:
			// 转储 DOS Stub (DOS 头之后，NT 头之前的部分，通常是一段 "This program cannot be run in DOS mode" 代码)
			WritePos = static_cast<char*>(pFileBuffer) + sizeof(IMAGE_DOS_HEADER);
			DumpSize = DOS_Offset - sizeof(IMAGE_DOS_HEADER);
			break;

		case NT:
			// 转储 NT 头 (包括 FileHeader 和 OptionalHeader)
			WritePos = static_cast<char*>(pFileBuffer) + DOS_Offset;
			DumpSize = offsetof(IMAGE_NT_HEADERS, OptionalHeader) + OPTION_Offset;
			break;

		case SectionTable:
			// 转储节表 (Section Table)，即所有 IMAGE_SECTION_HEADER 结构体
			WritePos = static_cast<char*>(pFileBuffer) + DOS_Offset + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + OPTION_Offset;
			DumpSize = pNtHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
			break;

		case SectionInfo:
			// 转储特定节区的**原始数据** (Raw Data)
			if (SectionName == nullptr) {
				CloseHandle(hFile);
				return false;
			}
			{
				// 定位到节表起始位置
				IMAGE_SECTION_HEADER* pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
					static_cast<char*>(pFileBuffer) + DOS_Offset +
					offsetof(IMAGE_NT_HEADERS, OptionalHeader) + OPTION_Offset
					);

				// 遍历查找匹配的节名
				for (int SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
					// 比较节名 (注意：节名不一定以 \0 结尾，但 strcmp 遇到 \0 会停，这里假设名字是标准的)
					// 更安全的做法是使用 memcmp 比较 8 字节
					if (strcmp((char*)pSectionHeader->Name, SectionName) == 0) { // 修正：strcmp 成功返回 0，原代码写的是 == NULL 也是对的
						// 定位到该节在文件中的原始数据偏移 (PointerToRawData)
						WritePos = static_cast<char*>(pFileBuffer) + pSectionHeader->PointerToRawData;
						// 大小为该节在文件中的占用大小 (SizeOfRawData)
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

		// 执行写入
		if (DumpSize > 0 && WritePos != nullptr) {
			RTN = WriteFile(hFile, WritePos, DumpSize, &WriteBytes, NULL);
		}

		CloseHandle(hFile);

		// 检查是否写入成功且字节数匹配
		if (RTN && DumpSize == WriteBytes) return true;
	}
	return false;
}

/**
 * @brief 运行一个可执行文件并将其进程内存镜像转储到磁盘 (Memory Dump)
 *
 * @param ExecuteFile [in] 要运行的可执行文件路径
 * @param DumpFile [in] 内存镜像保存路径
 * @return bool 成功返回 true
 *
 * @warning 此函数会启动进程并立即终止它，仅用于获取加载后的内存布局。
 *          对于加壳程序或依赖初始化的程序，这种方式获取的内存可能不完整或不正确。
 */
bool PE::MemoryDump(const wchar_t* ExecuteFile, const wchar_t* DumpFile) {
	STARTUPINFOW si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	si.cb = sizeof(STARTUPINFOW);

	MODULEINFO ModInfo = { 0 };
	SIZE_T ReadBytes = 0;
	void* pMemoryImage = nullptr;

	// 构建命令行缓冲区
	wchar_t szCommandLine[MAX_PATH * 2] = { 0 };
	wcsncpy_s(szCommandLine, ExecuteFile, _TRUNCATE); // 建议使用 _TRUNCATE 防止溢出

	// 1. 创建进程 (挂起或直接运行，此处未挂起，存在竞态条件风险，但在简单场景下可用)
	// CREATE_NO_WINDOW: 不创建窗口
	if (CreateProcessW(NULL, (LPWSTR)szCommandLine, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {

		HMODULE BaseAddress = nullptr;
		DWORD Need = 0;

		// 2. 枚举进程模块，获取主模块基址
		// 注意：EnumProcessModules 需要目标进程有查询权限
		if (EnumProcessModules(pi.hProcess, &BaseAddress, sizeof(BaseAddress), &Need)) {
			if (BaseAddress) {
				// 3. 获取模块详细信息 (基址、映像大小等)
				if (GetModuleInformation(pi.hProcess, BaseAddress, &ModInfo, sizeof(MODULEINFO))) {

					// 4. 在本地分配足够大的内存
					pMemoryImage = VirtualAlloc(NULL, ModInfo.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

					if (pMemoryImage) {
						// 5. 读取远程进程内存到本地缓冲区
						// 读取整个映像大小 (SizeOfImage) 或 读取字节数不足 (可能进程被保护或内存未提交)
						if (!ReadProcessMemory(pi.hProcess, ModInfo.lpBaseOfDll, pMemoryImage, ModInfo.SizeOfImage, &ReadBytes) || ReadBytes != ModInfo.SizeOfImage) {
							// 如果读取失败
							VirtualFree(pMemoryImage, 0, MEM_RELEASE);
							pMemoryImage = nullptr;
						}
					}
				}
			}
		}

		// 6. 清理：终止进程并关闭句柄
		// 注意：这里直接 TerminateProcess 是非常暴力的，可能导致文件占用或资源泄露，但在 Dump 工具中常见
		TerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}

	// 如果内存读取失败，直接返回
	if (!pMemoryImage) return false;

	// 7. 将内存镜像写入文件
	DWORD WriteBytes = 0;
	HANDLE hFile = CreateFileW(DumpFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if (hFile != INVALID_HANDLE_VALUE) {
		WriteFile(hFile, pMemoryImage, ModInfo.SizeOfImage, &WriteBytes, NULL);
		CloseHandle(hFile);
	}

	// 释放本地分配的内存
	VirtualFree(pMemoryImage, 0, MEM_RELEASE);

	// 检查 WriteBytes 是否等于 SizeOfImage
	return WriteBytes == ModInfo.SizeOfImage;
}

/**
 * @brief 将 RVA (相对虚拟地址) 转换为 FOA (文件偏移地址)
 *
 * @param pBuffer [in] PE 文件内存缓冲区
 * @param RVA [in] 需要转换的相对虚拟地址
 * @return DWORD 成功返回文件偏移地址 (FOA)，失败返回 -1
 *
 * @note 转换逻辑:
 * 1. 如果 RVA 在文件头范围内 (0 ~ SizeOfHeaders)，则 RVA == FOA。
 * 2. 否则，遍历节表，找到 RVA 所在的节。
 * 3. 计算 RVA 在该节内的偏移量，加上该节的文件起始偏移 (PointerToRawData)。
 */
DWORD PE::RvaToFoa(void* pBuffer, DWORD RVA) {
	if (pBuffer == nullptr) return -1;

	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	// 1. 验证 PE 有效性并获取 NT 头指针
	if (IsValid(pBuffer, pNtHeader)) {
		// 2. 边界检查：如果 RVA 超过映像大小，无效
		if (RVA > pNtHeader->OptionalHeader.SizeOfImage) return -1;

		// 3. 特殊情况：文件头区域
		// 在 SizeOfHeaders 范围内的数据，文件偏移与虚拟地址是一致的
		if (RVA < pNtHeader->OptionalHeader.SizeOfHeaders) return RVA;

		// 4. 定位节表 (Section Table) 起始位置
		// 计算公式: NT头基址 + Signature(4字节) + FileHeader(20字节) + OptionalHeaderSize
		// 注意：这里通过指针运算手动计算偏移，也可以直接使用 offsetof
		IMAGE_SECTION_HEADER* pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
			(char*)pNtHeader + sizeof(pNtHeader->Signature) +
			sizeof(IMAGE_FILE_HEADER) + pNtHeader->FileHeader.SizeOfOptionalHeader
			);

		// 5. 遍历所有节
		for (DWORD SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			// 获取当前节的虚拟地址范围 [VAStart, VAEnd]
			DWORD VAStart = pSectionHeader->VirtualAddress;
			// 注意：这里使用 VirtualSize (内存中的实际大小) 来判断范围
			DWORD VAEnd = pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize;

			// 判断 RVA 是否落在当前节内
			if (RVA >= VAStart && RVA < VAEnd) { // 建议改为 < VAEnd 以避免边界重叠问题，原代码 <= 也可
				// 计算 RVA 相对于节起始地址的偏移量
				DWORD RVA_Offset = RVA - VAStart;

				// 返回：节的文件起始偏移 + 节内偏移
				return pSectionHeader->PointerToRawData + RVA_Offset;
			}
			pSectionHeader++; // 移动到下一个节表项
		}
	}
	// 未找到对应的节或验证失败
	return -1;
}

/**
 * @brief 将 FOA (文件偏移地址) 转换为 RVA (相对虚拟地址)
 *
 * @param pBuffer [in] PE 文件内存缓冲区
 * @param FileSize [in] 文件总大小 (用于边界检查)
 * @param FOA [in] 需要转换的文件偏移地址
 * @return DWORD 成功返回相对虚拟地址 (RVA)，失败返回 -1
 *
 * @note 转换逻辑:
 * 1. 如果 FOA 在文件头范围内，则 FOA == RVA。
 * 2. 否则，遍历节表，找到 FOA 所在的节 (基于 PointerToRawData 和 SizeOfRawData)。
 * 3. 计算 FOA 在该节内的偏移量，加上该节的虚拟起始地址 (VirtualAddress)。
 */
DWORD PE::FoaToRva(void* pBuffer, DWORD FileSize, DWORD FOA) {
	if (pBuffer == nullptr) return -1;

	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pBuffer, pNtHeader)) {
		// 1. 边界检查：如果 FOA 超过文件实际大小，无效
		if (FOA > FileSize) return -1;

		// 2. 特殊情况：文件头区域
		if (FOA < pNtHeader->OptionalHeader.SizeOfHeaders) return FOA;

		// 3. 定位节表起始位置 (逻辑同 RvaToFoa)
		IMAGE_SECTION_HEADER* pSectionHeader = reinterpret_cast<IMAGE_SECTION_HEADER*>(
			(char*)pNtHeader + sizeof(pNtHeader->Signature) +
			sizeof(IMAGE_FILE_HEADER) + pNtHeader->FileHeader.SizeOfOptionalHeader
			);

		// 4. 遍历所有节
		for (DWORD SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			// 获取当前节的文件偏移范围 [FAStart, FAEnd]
			DWORD FAStart = pSectionHeader->PointerToRawData;
			// 注意：这里使用 SizeOfRawData (文件中的占用大小) 来判断范围
			DWORD FAEnd = pSectionHeader->PointerToRawData + pSectionHeader->SizeOfRawData;

			// 判断 FOA 是否落在当前节的文件范围内
			// 注意：如果 SizeOfRawData 为 0 (如 .bss 节在文件中不占空间)，此循环会跳过，这是正确的
			if (FOA >= FAStart && FOA < FAEnd) {
				// 计算 FOA 相对于节文件起始位置的偏移量
				DWORD FOA_Offset = FOA - pSectionHeader->PointerToRawData;

				// 返回：节的虚拟起始地址 + 节内偏移
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

	// 1. 验证 PE 有效性
	if (IsValid(pFileBuffer, pNtHeader)) {
		DWORD FileOffset = 0;

		// 2. 获取导出表的数据目录项 (Data Directory Entry for Export)
		IMAGE_DATA_DIRECTORY DataDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		// 3. 分配主结构体内存
		out_pExpInfo = static_cast<ExportInfo*>(calloc(1, sizeof(ExportInfo)));
		if (out_pExpInfo == nullptr) return false;

		// 4. 检查是否存在导出表
		if (DataDir.VirtualAddress == 0 || DataDir.Size == 0) {
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return false;
		}

		// 5. 将导出目录的 RVA 转换为文件偏移 (FOA)
		FileOffset = RvaToFoa(pFileBuffer, DataDir.VirtualAddress);
		if (FileOffset == DWORD(-1)) {
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return false;
		}

		// 6. 定位到 IMAGE_EXPORT_DIRECTORY 结构
		IMAGE_EXPORT_DIRECTORY* pExportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
			static_cast<char*>(pFileBuffer) + FileOffset
		);

		// 7. 获取并保存 PE 文件名 (DLL Name)
		FileOffset = RvaToFoa(pFileBuffer, pExportDir->Name);
		if (FileOffset == DWORD(-1)) {
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return false;
		}
		char* FileName = static_cast<char*>(pFileBuffer) + FileOffset;

		// 假设 ExportInfo.PEName 是一个固定大小的字符数组 (如 char PEName[256])
		strcpy_s(out_pExpInfo->PEName, FileName);
		out_pExpInfo->ExportFuncSize = 0;

		// 8. 初始化函数信息数组
		// 先分配一个元素的空间，后续根据需要 realloc 扩容
		FuncInfo* pFunctionsInfo = static_cast<FuncInfo*>(calloc(1, sizeof(FuncInfo)));
		if (pFunctionsInfo == nullptr) {
			free(out_pExpInfo);
			out_pExpInfo = nullptr;
			return false;
		}
		int RealFunctions = 0;	// 实际解析到的有名函数数量
		DWORD FuncIndex = 0;

		// --- 准备三个关键数组的指针 ---

		// A. 函数地址表 (AddressOfFunctions): 存储函数的 RVA
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
		// B. 名称序号映射表 (AddressOfNameOrdinals): 存储函数名对应的序号索引
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
		// C. 函数名称表 (AddressOfNames): 存储函数名字符串的 RVA
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
		// 9. 遍历导出函数 (如下是作者犯过的错，如下是修正之后的代码)
		// 注意：循环范围通常是从 0 到 NumberOfNames - 1
		// 原代码逻辑：从 (Base - 1) 开始遍历到 NumberOfFunctions。
		// 修正逻辑说明：
		// AddressOfNames 的大小是 NumberOfNames。
		// AddressOfFunctions 的大小是 NumberOfFunctions。
		// 只有有名字的函数才会出现在 AddressOfNames 和 AddressOfNameOrdinals 中。
		// 因此，循环应该基于 NumberOfNames 进行遍历，通过 Ordinal 索引去查 AddressOfFunctions。

		for (FuncIndex = 0; FuncIndex < pExportDir->NumberOfFunctions; FuncIndex++) {

			// 获取当前函数在 AddressOfFunctions 表中的索引 (Ordinal)
			WORD OrdinalIndex = pFuncOrdinals[FuncIndex];

			// 安全性检查：防止序号越界
			if (OrdinalIndex >= pExportDir->NumberOfFunctions) break;

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
			// 获取当前要填充的结构体指针
			FuncInfo* pCurrentFunctionsInfo = reinterpret_cast<FuncInfo*>(
				(char*)pFunctionsInfo + sizeof(FuncInfo) * RealFunctions
			);

			// 填入 函数地址RVA 和 序号
			// 这里的 Ordinal 应该是真实的序号 = Base + OrdinalIndex
			pCurrentFunctionsInfo->RVA_Address = pFuncAddr[pExportDir->Base + FuncIndex];
			pCurrentFunctionsInfo->Ordinal = pFuncOrdinals[FuncIndex];

			// 当前指向为 函数名RVA 块(4 bytes), 需要再进行一次 RvaToFoa
			FileOffset = RvaToFoa(pFileBuffer, FuncNameOffset[FuncIndex]);
			if (FileOffset == DWORD(-1)) {
				free(out_pExpInfo->Fn);
				free(out_pExpInfo);
				out_pExpInfo = nullptr;
				return false;
			}
			// 直接指向缓冲区内的函数名称字符串，无需复制 (节省内存，但依赖 pFileBuffer 生命周期)
			pCurrentFunctionsInfo->Name = static_cast<char*>(static_cast<char*>(pFileBuffer) + FileOffset);

			RealFunctions++;
		}
		// 10. 保存结果
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

/**
 * @brief 执行 PE 重定位 (Base Relocation)
 *
 * 当 PE 文件被加载到与首选基址 (ImageBase) 不同的内存地址时，必须修正代码中的所有绝对地址引用。
 * 此函数遍历重定位表，计算偏移量 (Delta)，并修正所有需要重定位的地址。
 *
 * @param pMemoryImage [in/out] 已加载到内存的 PE 图像 (当前地址可能不是首选基址)
 * @param pRemoteImage [in] 目标实际运行地址 (通常与 pMemoryImage 相同，除非是在远程进程操作)
 * @return bool 成功返回 true。如果没有重定位表或不需要重定位 (Delta=0)，也返回 true。
 */
bool PE::Relocation(void* pMemoryImage, void* pRemoteImage) {
	if (pMemoryImage == nullptr) return false;
	if (pRemoteImage == nullptr) return false;
	IMAGE_NT_HEADERS* pNtHeader = nullptr;

	// 1. 验证 PE 有效性
	if (IsValid(pMemoryImage, pNtHeader)) {

		// 2. 获取重定位表 (Base Relocation Table) 的数据目录
		IMAGE_DATA_DIRECTORY DataDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		
		// 如果没有重定位表或大小为0，说明不需要重定位 (或者是一个无法重定位的驱动/EXE)，直接返回成功
		if (DataDir.VirtualAddress == 0 || DataDir.Size == 0) return true;

		// 3. 定位重定位表起始位置
		IMAGE_BASE_RELOCATION* pBaseReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
			static_cast<char*>(pMemoryImage) + DataDir.VirtualAddress
		);

		// 4. 计算基址差值 (Delta)  Delta = 实际加载地址 - 首选基址 (ImageBase)
		// 
		ULONG_PTR Delta = (ULONG_PTR)pRemoteImage - (ULONG_PTR)pMemoryImage;

		// 如果差值为 0，说明加载地址与预期一致，无需重定位
		if (Delta == 0) return true;

		// 5. 遍历重定位块 (Block)
		// 重定位表由多个 IMAGE_BASE_RELOCATION 块组成，以 VirtualAddress 为 0 结束
		while (pBaseReloc->VirtualAddress) {
			// 计算当前块中的重定位项数量
			// SizeOfBlock 包含头结构大小，减去头大小后除以 WORD (2字节) 即为项数
			WORD RelocCount = static_cast<WORD>((pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD));
			// 指向当前块的具体重定位项数组 (紧接在头结构之后)
			WORD* pRelocBlock = reinterpret_cast<WORD*>((char*)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));

			// 6. 遍历块内的每一项
			for (DWORD RelocIndex = 0; RelocIndex < RelocCount; RelocIndex++) {
				// 每一项是一个 WORD (16位):
				// 高 4 位: 类型 (Type)
				// 低 12 位: 偏移量 (Offset)，相对于当前块的 VirtualAddress
				WORD RelocType = pRelocBlock[RelocIndex] >> 12;
				WORD RelocOffset = pRelocBlock[RelocIndex] & 0x0FFF;
				if (RelocType == IMAGE_REL_BASED_HIGHLOW || RelocType == IMAGE_REL_BASED_DIR64) {
					// 计算需要修改的地址在内存中的实际位置
					ULONG_PTR* pRelocAddr = reinterpret_cast<ULONG_PTR*>(
						static_cast<char*>(pMemoryImage) + pBaseReloc->VirtualAddress + RelocOffset
					);
					// 执行修正：原始地址 + Delta = 新地址
					*pRelocAddr += Delta;
				}
			}
			// 移动到下一个重定位块
			pBaseReloc = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
				(char*)pBaseReloc + pBaseReloc->SizeOfBlock
			);
		}
		return true;
	}
	return false;
}

/**
 * @brief 设置本地进程内存中各节区的保护属性 (VirtualProtect)
 *
 * 根据 PE 头中节表 (Section Table) 的特征标志 (Characteristics)，
 * 设置内存页的读写执行权限 (如 PAGE_EXECUTE_READ, PAGE_READWRITE 等)。
 *
 * @param pFileBuffer [in] PE 文件缓冲区 (用于读取节表信息)
 * @param pMemoryImage [in] 已加载到内存的 PE 图像 (用于修改属性)
 * @return bool 成功返回 true
 */
bool PE::SetSectionProperty(void* pFileBuffer, void* pMemoryImage) {
	if (pFileBuffer == nullptr) return false;
	if (pMemoryImage == nullptr) return false;

	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader)) {
		// 获取第一个节表项的指针 (使用 SDK 宏更安全)
		IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

		for (int SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			// 1. 根据节特征标志确定初始保护属性
			// 默认为只读
			DWORD memProperty = PAGE_READONLY;

			// 检查是否可执行 (IMAGE_SCN_MEM_EXECUTE)
			if (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				// 如果既可执行又可写 (IMAGE_SCN_MEM_WRITE) -> PAGE_EXECUTE_READWRITE (极少见，通常不安全)
				// 如果只可执行 -> PAGE_EXECUTE_READ
				memProperty = (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE)
					? PAGE_EXECUTE_READWRITE
					: PAGE_EXECUTE_READ;
			}
			// 检查是否可写 (但未标记可执行)
			else if (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE) {
				memProperty = PAGE_READWRITE;
			}
			// 其他情况保持 PAGE_READONLY (例如纯数据节 .rdata)

			// 2. 计算该节在内存中的起始地址
			void* pSectionAddr = (char*)pMemoryImage + pSectionHeader[SectionIndex].VirtualAddress;

			DWORD oldmemPropery = 0;
			// 3. 调用 Windows API 修改内存保护属性
			// 范围：节的虚拟大小 (VirtualSize)，确保覆盖节在内存中的实际占用
			if (!VirtualProtect(pSectionAddr, pSectionHeader[SectionIndex].Misc.VirtualSize, memProperty, &oldmemPropery)) {
				// 可选：记录错误，但这里继续尝试下一个节
			}

			pSectionHeader++; // 移动到下一个节表项
		}
		return true;
	}
	return false;
}

/**
 * @brief 设置远程进程内存中各节区的保护属性 (VirtualProtectEx)
 *
 * 功能同上，但针对的是另一个进程 (hProcess) 中的内存空间。
 * 常用于 DLL 注入后，在远程进程中修复内存属性。
 *
 * @param hProcess [in] 目标远程进程的句柄 (需 PROCESS_VM_OPERATION 权限)
 * @param pFileBuffer [in] PE 文件缓冲区 (用于读取节表信息)
 * @param pMemoryImage [in] 远程进程中已加载的 PE 图像基址
 * @return bool 成功返回 true
 */
bool PE::SetSectionProperty(HANDLE hProcess, void* pFileBuffer, void* pMemoryImage) {
	if (pFileBuffer == nullptr) return false;
	if (pMemoryImage == nullptr) return false;
	if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) return false;

	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	if (IsValid(pFileBuffer, pNtHeader)) {
		IMAGE_SECTION_HEADER* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);

		for (int SectionIndex = 0; SectionIndex < pNtHeader->FileHeader.NumberOfSections; SectionIndex++) {
			DWORD memProperty = PAGE_READONLY;

			// 逻辑同上：根据 Characteristics 决定属性
			if (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
				memProperty = (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE)
					? PAGE_EXECUTE_READWRITE
					: PAGE_EXECUTE_READ;
			}
			else if (pSectionHeader[SectionIndex].Characteristics & IMAGE_SCN_MEM_WRITE) {
				memProperty = PAGE_READWRITE;
			}

			// 计算远程进程中的节地址
			void* pSectionAddr = (char*)pMemoryImage + pSectionHeader[SectionIndex].VirtualAddress;

			DWORD oldmemPropery = 0;
			// 使用 VirtualProtectEx 操作远程进程内存
			if (!VirtualProtectEx(hProcess, pSectionAddr, pSectionHeader[SectionIndex].Misc.VirtualSize, memProperty, &oldmemPropery)) {
				// 失败处理 (如权限不足)
			}

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
	/*
	DWORD FileSize = 0;
	void* pFile = PE::Read(L"C:\\Users\\OMEN\\Desktop\\KernelBase.dll", FileSize);
	PE::ResourceInfo Res = { 0 };
	PE::GetResourceTable(pFile, PE::Icon , Res);
	*/

	
	DWORD FileSize = 0;
	void* pFile = PE::Read(L"C:\\Users\\OMEN\\Desktop\\KernelBase.dll", FileSize);
	PE::ExportInfo* pExp = nullptr;
	PE::GetExportTable(pFile, pExp);
	for (int i = 0; i < pExp->ExportFuncSize / sizeof(PE::FuncInfo); i++) {
		PE::FuncInfo* pCurrent = (PE::FuncInfo*)((char*)pExp->Fn + sizeof(PE::FuncInfo) * i);
		std::cout  << pCurrent->Ordinal << "\t\t" <<  pCurrent->RVA_Address << "\t\t" <<  pCurrent->Name << "\r\n";
	}
	
	
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

