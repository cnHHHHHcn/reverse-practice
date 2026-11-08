#pragma once

#include <iostream>
#include <vector>

#include "PEParser.h"
//#include "PDBParser.h"

int PE_demo();

int PDB_demo();

int main(){
	PE_demo();
	// PDB_demo();
}

struct DllMainParam {
	HMODULE hModule;
	DWORD  dwReason;
	LPVOID lpReserved;
};

int PDB_demo() {
	/*
	DWORD FileSize = 0;
	void* pFile = nullptr;
	PDB::Read(L"C:\\Users\\OMEN\\Desktop\\MFCLibpvzCheat.pdb", pFile, FileSize);
	// 假设 pFileData 是已加载到内存的文件基址
	PDB::MSF_SUPER_BLOCK* pSuper = nullptr;
	PDB::IsValid(pFile, pSuper);
	DWORD StreamDirectoryPointerOffset = pSuper->BlockMapAddr * pSuper->BlockSize;
	DWORD StreamDirectoryPointerCount = (pSuper->NumberOfDirectoryBytes + pSuper->BlockSize) / pSuper->BlockSize;
	DWORD* msf_StreamDir = reinterpret_cast<DWORD*>(
		static_cast<char*>(pFile) + StreamDirectoryPointerOffset
	);
	for (DWORD index = 0; index < StreamDirectoryPointerCount; index++) {
		DWORD StreamDirectoryOffset = msf_StreamDir[index] * pSuper->BlockSize;
		PDB::MSF_STREAM_DIRECTORY* pStreamDir = reinterpret_cast<PDB::MSF_STREAM_DIRECTORY*>(
			static_cast<char*>(pFile) + StreamDirectoryOffset
		);
		DWORD StreamDirectoryCount = pStreamDir->NumberOfStreams;
		DWORD* StreamDirectoryPage = reinterpret_cast<DWORD*>(
			static_cast<char*>(pFile) + (StreamDirectoryCount + 1) * sizeof(DWORD)
		);
		std::cout << std::hex;
		for (DWORD j = 0; j < StreamDirectoryCount; j++) {
			DWORD SysbolSize = pStreamDir->StreamSizes[j];
			DWORD SysbolOffset = StreamDirectoryPage[j] * pSuper->BlockSize;
			std::cout << SysbolOffset << std::endl;
		}
	}
	std::cout << std::dec;
	*/
	return 0;
}

int PE_demo() {
	
	PE::STATUS status = PE::PE_STATUS_SUCCESS;
	DllMainParam dmp = { 0 };
	DWORD pid = 3492;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	void* pFile = nullptr;
	DWORD FileSize = 0;
	DWORD ImageSize = 0;
	DWORD OEP_Entry = 0;
	HMODULE hLocalMod = nullptr;
	HMODULE hRemoteMod = nullptr;
	PE::Read(L"C:\\Users\\OMEN\\Desktop\\MFCLibpvzCheat64.dll", pFile, FileSize);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if(hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to open process." << std::endl;
		return -1;
	}
	PE::GetSizeOfImage(pFile, ImageSize);
	hRemoteMod = (HMODULE)VirtualAllocEx(hProcess, NULL, ImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (hRemoteMod == nullptr) {
		std::cerr << "Failed to allocate memory in remote process." << std::endl;
		return -1;
	}

	PE::BuildMemoryImage(pFile, hLocalMod);
	if (hLocalMod == nullptr) {
		std::cerr << "Failed ";
		return -1;
	}

	status = PE::FixImportTable(pid, hLocalMod);
	status = PE::Relocation(hLocalMod, hRemoteMod);
	WriteProcessMemory(hProcess, hRemoteMod, hLocalMod, ImageSize, NULL);
	status = PE::SetSectionProperty(hProcess, pFile, hRemoteMod);

	PE::GetEntryPoint(pFile, OEP_Entry);

	void* a = (void*)((char*)hRemoteMod + OEP_Entry);

	dmp.hModule = hRemoteMod;
	dmp.dwReason = DLL_PROCESS_ATTACH;
	dmp.lpReserved = NULL;
	hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)a, &dmp, 0, NULL);
	if (hThread == nullptr) {
		std::cerr << "Failed to Create Remote Thread" << std::endl;
		return -1;
	}
	//WaitForSingleObject(hThread, INFINITE);
	//VirtualFreeEx(hProcess, hRemoteMod, 0, MEM_RELEASE);
	//VirtualFree(hLocalMod, 0, MEM_RELEASE);
	//CloseHandle(hThread);
	//CloseHandle(hProcess);
	

	/*	// 抹除导入表的函数名称
	void* pFile = nullptr;
	DWORD FileSize = 0;
	PE::Read(L"C:\\Users\\OMEN\\Desktop\\MFCLibpvzCheat64.dll", pFile, FileSize);
	PE::ClearImportFunctionName(pFile);
	PE::FileDump(pFile, FileSize, L"C:\\Users\\OMEN\\Desktop\\MFCLibpvzCheat64_import.dll");
	HMODULE hModule = LoadLibraryW(L"C:\\Users\\OMEN\\Desktop\\MFCLibpvzCheat64_import.dll");
	hModule = 0;
	*/

	/*	// 获取 PDB文件信息
	DWORD FileSize = 0;
	void* pFile = nullptr;
	PE::STATUS a = PE::Read(L"C:\\Users\\OMEN\\Desktop\\KernelBase.dll", pFile, FileSize);
	PE::DebugInfo dbg = { 0 };
	PE::GetDebugTable(pFile, dbg);
	std::cout << std::hex;
	for (DWORD i = 0; i < dbg.Count; i++) {
		std::cout << dbg.Items[i].DebugData.RVA << "\t" << dbg.Items[i].DebugData.FOA << "\t" << dbg.Items[i].Size << '\t' << dbg.Items[i].Type << '\n';
	}
	std::cout << std::dec;
	void* cv = nullptr;
	char* pdbFile = nullptr;
	PE::GetDebugPDB(pFile, dbg, cv, pdbFile);
	system("chcp 65001");
	std::cout << pdbFile << std::endl;
	std::string pdbOrder;
	PE::GetSysPDB_URL(cv, pdbOrder);
	std::cout << pdbOrder;
	free(dbg.Items);
	*/

	/*	// 获取 TLS
	DWORD FileSize = 0;
	void* pFile = nullptr;
	PE::STATUS a = PE::Read(L"C:\\Users\\OMEN\\Desktop\\MFCLibpvzCheat64.dll", pFile, FileSize);
	PE::TLS_Info tls = { 0 };
	PE::GetTlsTable(pFile, tls);
	ULONGLONG Data = *(ULONGLONG*)((char*)pFile + tls.Data.FOA);
	DWORD Index = *(DWORD*)((char*)pFile + tls.Index.FOA);
	std::cout << std::hex;
	std::cout << "TLS Name\tTLS RVA\t\tTLS FOA\t\tTLS Value" << '\n';
	std::cout << "Data\t\t" << tls.Data.RVA << "\t\t" << tls.Data.FOA << "\t\t" << Data << "\t\t" << tls.DataSize << "\n";
	std::cout << "Index\t\t" << tls.Index.RVA << "\t\t" << tls.Index.FOA << "\t\t" << Index << "\n";
	std::cout << "Callback\t" << tls.Callback.RVA << "\t\t" << tls.Callback.FOA << "\t\t" << tls.CallbackCount << std::endl;
	std::cout << std::dec;
	*/

	/*	// 添加节区
	DWORD FileSize = 0;
	void* pFile = nullptr;
	PE::STATUS a = PE::Read(L"C:\\Users\\OMEN\\Desktop\\MFCLibpvzCheat64.dll", pFile, FileSize);
	IMAGE_NT_HEADERS* pNtHeader = nullptr;
	PE::SectionDataInfo NewSection = { 0 };
	NewSection.Characteristics = IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ;
	strcpy_s(NewSection.SectionName, 8, ".newsec");
	NewSection.DataSize = 0x843;
	NewSection.pSectionData = calloc(1, NewSection.DataSize);
	if (NewSection.pSectionData != nullptr) {
		memset(NewSection.pSectionData, 0x4141, NewSection.DataSize);
		PE::AddSection(pFile, NewSection, FileSize);
		PE::IsValid(pFile, pNtHeader);

		FILE* fp = nullptr;
		fopen_s(&fp, "C:\\Users\\OMEN\\Desktop\\MFCLibpvzCheat64_new.dll", "wb");
		if (fp == nullptr) {
			std::cerr << "Failed to create file." << std::endl;
			return -1;
		}
		size_t p = fwrite(pFile, 1, FileSize, fp);
		fclose(fp);
	}
	*/

	/*	// 计算熵值
	DWORD FileSize = 0;
	void* pFile = nullptr;
	PE::STATUS a = PE::Read(L"C:\\Users\\OMEN\\Desktop\\test_des.exe", pFile, FileSize);
	double entropy = 0.0;
	a = PE::CalculateEntropy(pFile, FileSize, entropy);
	std::cout << "Entropy: " << entropy << std::endl;
	VirtualFree(pFile, 0, MEM_RELEASE);
	*/

	/*	// 获取资源表
	DWORD FileSize = 0;
	void* pFile = nullptr;
	PE::STATUS a = PE::Read(L"C:\\Users\\OMEN\\Desktop\\test_src.exe", pFile, FileSize);
	PE::ResourceInfo ResInfo = { 0 };
	a = GetResourceTable(pFile, ResInfo, PE::Icon);
	for(int i = 0; i < ResInfo.Count; i++) {
		std::wcout << L"Type: " << ResInfo.Items[i].TypeName << L"\tName: " << ResInfo.Items[i].Name << L"\tLanguage: " << ResInfo.Items[i].Language << L"\tData RVA: " << std::hex << ResInfo.Items[i].Data.RVA << L"\tData FOA: " << std::hex << ResInfo.Items[i].Data.FOA << L"\tSize: " << ResInfo.Items[i].Size << std::endl;
	}
	a = PE::PE_STATUS_SUCCESS;
	VirtualFree(pFile, 0, MEM_RELEASE);
	*/


	/*	// 获取导出表
	DWORD FileSize = 0; WORD Bit = 0;
	void* pFile = nullptr;
	PE::STATUS a = PE::PE_STATUS_SUCCESS; 
	a = PE::Read(L"C:\\Users\\OMEN\\Desktop\\KernelBase.dll", pFile, FileSize);
	PE::ExportInfo pExp = { 0 };
	a = PE::GetExportTable(pFile, pExp);
	a = PE::PE_STATUS_SUCCESS;
	for (int i = 0; i < pExp.ExportFuncSize / sizeof(PE::FuncInfo); i++) {
		PE::FuncInfo* pCurrent = (PE::FuncInfo*)((char*)pExp.Fn + sizeof(PE::FuncInfo) * i);
		std::cout  << pCurrent->Ordinal << "\t\t" <<  pCurrent->Address.RVA << "\t\t" << pCurrent->Address.FOA << "\t\t" <<  pCurrent->Name << "\r\n";
	}
	free(pExp.Fn);
	VirtualFree(pFile, 0, MEM_RELEASE);
	*/

	/*	// PE 文件结构  内存、文件转化
	PE::STATUS a = PE::PE_STATUS_SUCCESS;
	a = PE::MemoryDump(L"C:\\Users\\OMEN\\Desktop\\test_src.exe", L"C:\\Users\\OMEN\\Desktop\\test_src_Mem.txt");
	std::cout << a << std::endl;
	void* pFile = nullptr;
	DWORD FileSize = 0;
	a = PE::Read(L"C:\\Users\\OMEN\\Desktop\\test_src_Mem.txt", pFile, FileSize);
	std::cout << a << std::endl;
	a = PE::MemoryToFileDump((HMODULE)pFile, L"C:\\Users\\OMEN\\Desktop\\test_src_file.exe");
	std::cout << a << std::endl;
	VirtualFree(pFile, 0, MEM_RELEASE);
	*/

	/*	// 计算校验和
	DWORD FileSum = 0, CheckSum = 0;
	//MapFileAndCheckSumW(L"C:\\Users\\OMEN\\Desktop\\test_src.exe", &FileSum, &CheckSum);
	DWORD FileSize = 0; bool RTN = false;
	void* pFile = nullptr;
	PE::STATUS a = PE::Read(L"C:\\Users\\OMEN\\Desktop\\test_src.exe", pFile, FileSize);
	PE::GetPEChecksum(pFile, FileSize, FileSum, CheckSum, RTN);
	VirtualFree(pFile, 0, MEM_RELEASE);
	*/

	/*	// Dump各个节区数据
	DWORD FileSize = 0;
	void* pFile = nullptr;
	PE::STATUS a = PE::Read(L"C:\\Users\\OMEN\\Desktop\\MFCLibpvzCheat64.dll", pFile, FileSize);
	void* pSectionName = nullptr;
	size_t SectionNameSize = 0;
	PE::FileSectionDump(pFile, PE::DOS, nullptr, L"D:\\MFCLibpvzCheat64-DOS.txt");
	PE::FileSectionDump(pFile, PE::DOS_stub, nullptr, L"D:\\MFCLibpvzCheat64-DOS_stub.txt");
	PE::FileSectionDump(pFile, PE::NT, nullptr, L"D:\\MFCLibpvzCheat64-NT.txt");
	PE::FileSectionDump(pFile, PE::SectionTable, nullptr, L"D:\\MFCLibpvzCheat64-SectionTable.txt");
	if (PE::GetSectionName(pFile, pSectionName, SectionNameSize) == PE::PE_STATUS_SUCCESS) {
		for (int Index = 0; Index < SectionNameSize / sizeof(char[8]); Index++) {
			std::cout << (char*)pSectionName + Index * sizeof(char[8]) << "\n";
			std::wstring out_File = L"D:\\MFCLibpvzCheat64-Section";
			out_File.append(1, 49 + Index);
			out_File.append(L".bin");
			PE::FileSectionDump(pFile, PE::SectionInfo, (char*)pSectionName + Index * sizeof(char[8]), out_File.c_str());
		}
	}
	free(pSectionName);
	VirtualFree(pFile, 0, MEM_RELEASE);
	*/
	return 0;
}
