#pragma once

// 如果使用方会使用智能指针的话，请把下一行的注释去掉，核心使用规范与重要注意事项中的 Part1 可以忽略
// #include <memory>

#include <string>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
//#include <ImageHlp.h>

//#pragma comment(lib, "ImageHlp.lib")
#define ALIGN_UP(Size, align) (((Size) + (align) - 1) & ~((align) - 1))

#define GetRVA(VA, ImageBase) ((DWORD)((ULONG_PTR)(VA) - (ULONG_PTR)(ImageBase)))

static uintptr_t GetModuleBaseAddress(DWORD pid, const wchar_t* Module);

/*
* 1. RVA 与 FOA 互转 (RVA <-> File Offset)  yes
* 2. 获取导入表 (Import Table)				yes
* 3. 获取导出表 (Export Table)				yes
* 4. 获取资源表 (Resource Table)			yes
* 5. 手动映射 (Manual Map)					pass
* 6. 重定位表处理 (Relocation Table)		yes
* 7. 校验和计算 (Checksum)					yes
* 8. 获取节区详细信息						pass easy
* 9. 壳检测 (Packers Detection)
*/

/*  核心使用规范与重要注意事项
*
* Part 1
* 调用 GetSectionName, GetExportTable，GetResourceTable，GetDebugTable 这些方法之后一定要记得调用 free(pointer);
* 调用 Read, BuildMemoryImage 方法之后一定要调用 VirtualFree(pointer, 0, MEM_RELEASE);
* 否则会发生内存泄露
*
* Part 2
* 为了防止架构不匹配导致的崩溃，如下函数
* MemoryToFileDump、GetExportTable、FixImportTable、AddSection、 Relocation、GetResourceTable
* 在执行核心逻辑前都会强制验证目标文件的平台位数。
*/

/*
 * 智能指针 针对 malloc、realloc、calloc 的安全写法
 * std::unique_ptr<void, decltype(&free)> upFile(pFile, &free);
 * 智能指针 针对 VirtualFree 的安全写法
 * std::unique_ptr<void, decltype(virtual_free_deleter)> ptr(pFile, virtual_free_deleter);
 */

 /*	哪里用了，放在哪里。
 // 使用 Lambda 表达式作为自定义删除器
 auto virtual_free_deleter = [](void* p) {
	 if (p) { // 建议加上判空保护，防止对 nullptr 调用 VirtualFree
		 VirtualFree(p, 0, MEM_RELEASE);
	 }
 };
 */

namespace PE {

	// 错误状态枚举，表示各种可能的错误情况
	enum STATUS {
		// 基础错误
		PE_STATUS_SUCCESS,							// 成功
		PE_STATUS_INVALID_PARAMETER,				// 无效参数
		PE_STATUS_INVALID_FORMAT,					// 无效的 PE 格式

		// 文件操作相关错误
		PE_STATUS_FILE_OPEN_FAILURE,				// 文件打开失败
		PE_STATUS_FILE_READ_FAILURE,				// 文件读取失败
		PE_STATUS_FILE_WRITE_FAILURE,				// 文件写入失败
		PE_STATUS_FILE_NOT_FOUND,					// 文件未找到
		PE_STATUS_FILE_ACCESS_DENIED,				// 文件访问被拒绝
		PE_STATUS_FILE_INVALID_SIZE,				// 文件大小无效

		// PE 结构相关错误
		PE_STATUS_SIZE_OF_IMAGE_OVERFLOW,			// SizeOfImage属性 大小溢出
		PE_STATUS_SECTION_HEADER_OUT_OF_RANGE,		// 节区表头超出范围
		PE_STATUS_SECTION_DATA_AREA_OUT_OF_RANGE,	// 节区数据区域超出范围
		PE_STATUS_ARCH_MISMATCH,					// 架构不匹配
		PE_STATUS_BUILD_IMAGE_FAILURE,				// 构建内存映像失败
		PE_STATUS_IMPORT_INT_MISSING,				// 导入表缺失 INT 信息
		PE_STATUS_FIX_IMPORT_FAILURE,				// 修复导入表失败
		PE_STATUS_GET_EXPORT_FAILURE,				// 获取导出表失败
		PE_STATUS_SET_SECTION_PROPERTY_FAILURE,		// 设置节属性失败
		PE_STATUS_GET_RESOURCE_FAILURE,				// 获取资源表失败
		PE_STATUS_GET_FOA_FAILURE,					// 获取 FOA 失败
		PE_STATUS_GET_RVA_FAILURE,					// 获取 RVA 失败
		PE_STATUS_GET_PDB_FILE_INFO_FAILURE,		// 获取 PDB 文件信息失败
		PE_STATUS_GET_PDB_FILE_URL_FAILURE,			// 获取 PDB 文件 URL 失败


		// 内存操作相关错误
		PE_STATUS_PROCESS_OPEN_FAILURE,				// 打开进程失败
		PE_STATUS_REMOTE_MEMORY_ALLOCATION_FAILURE,	// 远程内存分配失败
		PE_STATUS_REMOTE_MEMORY_WRITE_FAILURE,		// 远程内存写入失败
		PE_STATUS_REMOTE_MEMORY_READ_FAILURE,		// 远程内存读取失败
		PE_STATUS_LOCAL_MEMORY_ALLOCATION_FAILURE,	// 本地内存分配失败
		PE_STATUS_LOCAL_MEMORY_WRITE_FAILURE,		// 本地内存写入失败
		PE_STATUS_LOCAL_MEMORY_READ_FAILURE,		// 本地内存读取失败
		PE_STATUS_LOAD_MODULE_FAILURE,				// 加载模块失败
		PE_STATUS_GET_MODULE_BASE_FAILURE,			// 获取模块基址失败
		PE_STATUS_GET_MODULE_INFO_FAILURE,          // 获取模块信息失败
		PE_STATUS_MODULE_NOT_FOUND,					// 模块未找到
		PE_STATUS_MODULE_RANGE_NOT_IN				// 模块范围不在预期范围内
	};

	// 节区转储枚举，表示要转储的 PE 结构部分
	enum DumpStruct {
		DOS,
		DOS_stub,
		NT,
		SectionTable,
		SectionInfo
	};

	// 资源类型枚举，包含常见的 Windows 资源类型
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
		NoneResources = 0xFFFF
	};

	struct PE_Offset {
		DWORD RVA;					// 相对虚拟地址 (Relative Virtual Address)
		DWORD FOA;					// 文件偏移地址 (File Offset Address)
	};

	struct FuncInfo {
		WORD Ordinal;				// 函数序号
		PE_Offset Address;			// 函数的 RVA/FOA 地址
		char* Name;					// 函数名称 (如果有的话，某些导出可能没有名称只有序号)
	};

	struct ExportInfo {
		char PEName[48];			// PE 文件名
		DWORD FuncCount;			// 导出函数数量
		DWORD ExportFuncSize;		// 导出函数表大小 (字节)
		FuncInfo* Fn;				// 动态数组，存储所有导出函数的信息
	};

	struct ResourceItem {
		wchar_t TypeName[32];      // 类型名 (或 ID)
		wchar_t Name[64];          // 资源名 (或 ID)
		wchar_t Language[16];      // 语言 ID
		PE_Offset Data;            // 资源数据的 RVA/FOA 地址
		DWORD Size;                // 资源大小
	};

	struct ResourceInfo {
		DWORD Count;               // 资源总数
		ResourceItem* Items;       // 动态数组，存储所有找到的资源项
	};

	struct SectionDataInfo {
		char	SectionName[8];		// 节区名称，8 字节 (包含 null 终止符)
		DWORD   Characteristics;	// 节区属性
		void* pSectionData;		// 节数据指针
		DWORD	DataSize;			// 节数据大小
	};

	struct TLS_Info {
		PE_Offset	Data;			// TLS 数据的 RVA\FOA
		PE_Offset	Index;			// TLS 索引的 RVA\FOA
		PE_Offset	Callback;		// TLS 回调函数的 RVA\FOA
		DWORD		DataSize;		// TLS 数据长度
		DWORD		CallbackCount;	// TLS 回调函数个数
	};

	struct DebugItem {
		PE_Offset DebugData;		// 调试数据 RVA\FOA
		DWORD Size;					// 调试数据长度
		DWORD Type;					// 调试类型
	};

	struct DebugInfo {
		DWORD Count;				// 调试总数
		DebugItem* Items;			// 动态数组，存储所有找到的调试项
	};

	// DebugItem.Type  
	// Macro: IMAGE_DEBUG_TYPE_CODEVIEW
	// Value: 2

	const DWORD PDB20 = 0x3031424e;// '01BN'
	struct CodeViewInfo_PDB20 {
		DWORD CodeViewSignature;
		DWORD Signature;
		DWORD Age;
		char pdbFile[1];
	};

	const DWORD PDB70 = 0x53445352;// 'SDSR'
	struct CodeViewInfo_PDB70 {
		DWORD CodeViewSignature;
		GUID Signature;
		ULONG Age;
		char pdbFile[1];
	};



	STATUS Read(const wchar_t* FileName, void*& out_pFileBuffer, DWORD& out_FileSize);
	STATUS IsValid(void* pBuffer, IMAGE_NT_HEADERS*& out_pNtHeader);
	STATUS SetSizeOfImage(void* pFileBuffer, DWORD NewSizeOfImage);
	STATUS GetMachineType(void* pFileBuffer, WORD& out_MachineType);
	STATUS GetSubSystem(void* pFileBuffer, WORD& out_SubSystemInfo);
	STATUS GetEntryPoint(void* pFileBuffer, DWORD& out_OEP_Address);
	STATUS GetPeFormat(void* pFileBuffer, WORD& out_HDR);
	STATUS GetSectionName(void* pFileBuffer, void*& out_SectionName, size_t& SectionNameSize);
	STATUS GetPEChecksum(void* pFileBuffer, DWORD FileSize, DWORD& file_Checksum, DWORD& out_Checksum, bool& out_IsPass);
	STATUS FileSectionDump(void* pFileBuffer, DumpStruct Signature, char* SectionName, const wchar_t* DumpFile);
	STATUS MemoryDump(const wchar_t* ExecuteFile, const wchar_t* DumpFile);
	STATUS MemoryToFileDump(void* pMemoryImage, const wchar_t* DumpFile);
	DWORD RvaToFoa(void* pBuffer, DWORD RVA);
	DWORD FoaToRva(void* pBuffer, DWORD FOA);
	STATUS BuildMemoryImage(void* pFileBuffer, void*& pMemoryImage);
	STATUS GetExportTable(void* pFileBuffer, ExportInfo& out_ExpInfo);
	STATUS FixImportTable(DWORD pid, void* pMemoryImage/*, void* pRemoteImageBase*/);
	STATUS Relocation(void* pMemoryImage, void* pRemoteImageBase);
	STATUS SetSectionProperty(void* pFileBuffer, void* pMemoryImage);
	STATUS SetSectionProperty(HANDLE hProcess, void* pFileBuffer, void* pMemoryImage);
	STATUS GetResourceTable(void* pFileBuffer, ResourceInfo& ResInfo, ResourceType TypeID = NoneResources);
	STATUS GetTlsTable(void* pFileBuffer, TLS_Info& out_tls_Info);
	STATUS GetDebugTable(void* pFileBuffer, DebugInfo& out_dbgInfo);
	STATUS GetDebugPDB(void* pFileBuffer, DebugInfo dbgInfo, void*& out_cv_Info, char*& out_PdbFile);
	STATUS GetSysPDB_URL(void* cv_Info, std::string& out_URL);
	STATUS AddSection(void*& pFileBuffer, SectionDataInfo NewSection, DWORD& FileSize);
	STATUS CalculateEntropy(const void* buffer, size_t size, double& out_Entropy);
}