#pragma once

#include <string>
#include <windows.h>

namespace PDB {
	// 错误状态枚举，表示各种可能的错误情况
	enum STATUS {
		// 基础错误
		PDB_STATUS_SUCCESS,							// 成功
		PDB_STATUS_INVALID_PARAMETER,				// 无效参数
		PDB_STATUS_INVALID_FORMAT,					// 无效的 PDB 格式

		// 文件操作相关错误
		PDB_STATUS_FILE_OPEN_FAILURE,				// 文件打开失败
		PDB_STATUS_FILE_READ_FAILURE,				// 文件读取失败
		PDB_STATUS_FILE_WRITE_FAILURE,				// 文件写入失败
		PDB_STATUS_FILE_NOT_FOUND,					// 文件未找到
		PDB_STATUS_FILE_ACCESS_DENIED,				// 文件访问被拒绝
		PDB_STATUS_FILE_INVALID_SIZE,				// 文件大小无效

		// 内存操作相关错误
		PDB_STATUS_PROCESS_OPEN_FAILURE,			// 打开进程失败
		PDB_STATUS_REMOTE_MEMORY_ALLOCATION_FAILURE,// 远程内存分配失败
		PDB_STATUS_REMOTE_MEMORY_WRITE_FAILURE,		// 远程内存写入失败
		PDB_STATUS_REMOTE_MEMORY_READ_FAILURE,		// 远程内存读取失败
		PDB_STATUS_LOCAL_MEMORY_ALLOCATION_FAILURE,	// 本地内存分配失败
		PDB_STATUS_LOCAL_MEMORY_WRITE_FAILURE,		// 本地内存写入失败
		PDB_STATUS_LOCAL_MEMORY_READ_FAILURE,		// 本地内存读取失败
		PDB_STATUS_LOAD_MODULE_FAILURE,				// 加载模块失败
		PDB_STATUS_GET_MODULE_BASE_FAILURE,			// 获取模块基址失败
		PDB_STATUS_GET_MODULE_INFO_FAILURE,         // 获取模块信息失败
		PDB_STATUS_MODULE_NOT_FOUND,				// 模块未找到
		PDB_STATUS_MODULE_RANGE_NOT_IN,				// 模块范围不在预期范围内

		PDB_STATUS_DOWNLOAD_FAILURE,
	};

	typedef struct _MSF_SUPER_BLOCK {
		DWORD BlockSize;
		DWORD FreeBlockMapBlock;
		DWORD NumberOfBlocks;
		DWORD NumberOfDirectoryBytes;
		DWORD Unknown;
		DWORD BlockMapAddr;
	} MSF_SUPER_BLOCK, *PMSF_SUPER_BLOCK;

	// StreamBlocks =  = sizeof(DWORD) + (NumberOfStreams + 1)
	typedef struct _MSF_STREAM_DIRECTORY {
		DWORD NumberOfStreams;
		DWORD StreamSizes[1];
		// ULONG StreamBlocks[1];
	}MSF_STREAM_DIRECTORY, *PMSF_STREAM_DIRECTORY;

	// Signature: DS
	const WORD PDB_Signature = 0x5344;

	STATUS Downlaod_PDB_File(std::string PDB_URL);
	STATUS Read(const wchar_t* FileName, void*& out_pFileBuffer, DWORD& out_FileSize);
	STATUS IsValid(void* pFileBuffer, PMSF_SUPER_BLOCK& mfs_Super_Block);
	// STATUS
}