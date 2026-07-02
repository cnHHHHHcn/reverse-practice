#pragma once

#include "PDBParser.h"

PDB::STATUS PDB::Downlaod_PDB_File(std::string PDB_URL) {
	if (PDB_URL.empty()) return PDB_STATUS_INVALID_PARAMETER;

	return PDB_STATUS_SUCCESS;
}

PDB::STATUS  PDB::Read(const wchar_t* FileName, void*& out_pFileBuffer, DWORD& out_FileSize) {
	if (FileName == nullptr) return PDB_STATUS_INVALID_PARAMETER;
	void* out_param_test = nullptr;
	out_param_test = &out_pFileBuffer;
	if (out_param_test == nullptr) return PDB_STATUS_INVALID_PARAMETER;
	out_param_test = &out_FileSize;
	if (out_param_test == nullptr) return PDB_STATUS_INVALID_PARAMETER;

	BOOL apiRTN = FALSE;
	STATUS RTN = PDB_STATUS_SUCCESS;
	out_pFileBuffer = nullptr;
	DWORD ReadTotalBytes = NULL;
	if (GetFileAttributesW(FileName) == INVALID_FILE_ATTRIBUTES) return PDB_STATUS_FILE_NOT_FOUND;
	HANDLE hFile = CreateFileW(FileName, GENERIC_READ, NULL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != 0 && hFile != INVALID_HANDLE_VALUE) {
		LARGE_INTEGER FS;
		apiRTN = GetFileSizeEx(hFile, &FS);
		out_FileSize = static_cast<DWORD>(FS.QuadPart);
		if (apiRTN && out_FileSize != NULL) {
			out_pFileBuffer = VirtualAlloc(NULL, out_FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (out_pFileBuffer != nullptr) {
				apiRTN = ReadFile(hFile, out_pFileBuffer, out_FileSize, &ReadTotalBytes, NULL);
				if (apiRTN && out_FileSize == ReadTotalBytes) {
					CloseHandle(hFile);
					return PDB_STATUS_SUCCESS;
				}
				else RTN = PDB_STATUS_LOCAL_MEMORY_WRITE_FAILURE;
				free(out_pFileBuffer);
				out_pFileBuffer = nullptr;
			}
			else RTN = PDB_STATUS_LOCAL_MEMORY_ALLOCATION_FAILURE;
		}
		else RTN = PDB_STATUS_FILE_INVALID_SIZE;
		CloseHandle(hFile);
		return RTN;
	}
	return PDB_STATUS_FILE_OPEN_FAILURE;
}

PDB::STATUS PDB::IsValid(void* pFileBuffer, PMSF_SUPER_BLOCK& msf_Super_Block){
	if (pFileBuffer == nullptr) return PDB_STATUS_INVALID_PARAMETER;
	char* PDB_HeaderText = static_cast<char*>(pFileBuffer);
	int PDB_HeaderTextLength = strlen(PDB_HeaderText);
	WORD Signature = *(WORD*)(PDB_HeaderText + PDB_HeaderTextLength - sizeof(WORD));
	if (Signature == PDB_Signature) {
		msf_Super_Block = reinterpret_cast<PMSF_SUPER_BLOCK>(
			static_cast<char*>(pFileBuffer) + PDB_HeaderTextLength + 3	
		);
		return PDB_STATUS_SUCCESS;
	}
	return PDB_STATUS_INVALID_FORMAT;
}


