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

PROCESSENTRY32* GetProcessEntryInfo(DWORD& Count) {
	PROCESSENTRY32* Result = reinterpret_cast<PROCESSENTRY32*>(calloc(1, sizeof(PROCESSENTRY32)));
	if(Result == nullptr) {
		return nullptr;
	}
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE) {
		free(Result);
		return nullptr;
	}
	PROCESSENTRY32 temp;
	Count = 0;
	temp.dwSize = sizeof(PROCESSENTRY32);
	if(Process32First(hProcessSnap, &temp)) {
		do {
			if (temp.th32ProcessID != 0) {
				if (Count) {
					PROCESSENTRY32* newResult = reinterpret_cast<PROCESSENTRY32*>(realloc(Result, (Count + 1) * sizeof(PROCESSENTRY32)));
					if (newResult == nullptr) {
						free(Result);
						CloseHandle(hProcessSnap);
						return nullptr;
					}
					Result = newResult;
				}
				memcpy(&Result[Count], &temp, sizeof(PROCESSENTRY32));
				Count++;
			}
		} while (Process32Next(hProcessSnap, &temp));
	}
	CloseHandle(hProcessSnap);
	return Result;
}

void PrintProcessEntryInfo(PROCESSENTRY32* ProcessEntry, DWORD Count) {
	if (ProcessEntry == nullptr || Count == 0) {
		return;
	}
	system("cls");
	printf("PID\tProcess Name\n");
	for (DWORD i = 0; i < Count; i++) {
		wprintf(L"%u\t%s\n", ProcessEntry[i].th32ProcessID, ProcessEntry[i].szExeFile);
	}
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

/**
 * @brief 目标进程内存数据快照信息 (Memory Data Snapshot Information)
 *
 * 该结构体用于保存从目标进程中提取的一段内存数据的完整上下文。
 * 它不仅包含了目标进程中的原始虚拟地址，还包含了在本地进程中分配的
 * 内存缓冲区指针，实现了跨进程数据的“本地化映射”。
 *
 * @note 核心成员:
 * - OriginalAddress: 目标进程中的绝对虚拟地址（用于后续跨进程写入或校验）。
 * - DataAddress: 本地进程中由 VirtualAlloc 分配的缓冲区指针（用于本地分析）。
 * - Size: 该内存快照的总字节数（同时也是越界保护的边界上限）。
 */
typedef struct _MEMORY_DATA_INFORMATION {
	PVOID OriginalAddress;  // [in] 目标进程中的原始虚拟内存地址
	PVOID DataAddress;      // [in] 本地进程中的内存缓冲区基址
	size_t Size;            // [in] 内存缓冲区的总大小（字节数）
} MEMORY_DATA_INFORMATION, * PMEMORY_DATA_INFORMATION;

/**
 * @brief 目标进程全局内存布局信息 (Process Memory Layout Information)
 *
 * 该结构体用于保存由 ScanMemory 函数遍历获取的内存区域（Region）列表。
 * 它是整个内存引擎的“地图”，后续所有的内存读取、解析和写入操作，
 * 都需要基于此结构体提供的布局信息来进行边界校验。
 *
 * @note 核心成员:
 * - dwSize: 内存信息数组占用的总字节数（可通过除以 sizeof(MEMORY_BASIC_INFORMATION) 获取区域总数）。
 * - MemBasicInfo: 指向动态分配的 MEMORY_BASIC_INFORMATION 数组的指针。
 *
 * @warning 资源释放责任:
 * MemBasicInfo 指向的内存是由 ScanMemory 内部动态分配的，
 * 调用者在不再需要该内存布局信息时，必须负责调用 free() 释放，防止内存泄漏。
 */
typedef struct _MEMORY_INFORMATION {
	ULONGLONG dwSize;                   // [in] MemBasicInfo 数组的总字节大小
	PMEMORY_BASIC_INFORMATION MemBasicInfo; // [in] 指向内存区域属性数组的指针
} MEMORY_INFORMATION, * PMEMORY_INFORMATION;

/**
 * @brief 内存操作参数信息 (Memory Operation Parameters)
 *
 * 该结构体作为执行内存读取（ReadMemory）或写入（WriteMemory）操作的
 * 统一输入参数。它将“操作目标”与“操作数据”进行了封装，使函数接口更加简洁。
 *
 * @note 核心成员:
 * - DataAddress: 指向本地数据的指针。在写入时，它是数据源；在读取时，它是数据接收缓冲区。
 * - Size: 本次操作需要读取或写入的数据大小（字节数）。
 * - Offset: 目标操作位置相对于 OriginalAddress 的偏移量。
 *
 * @warning 安全约束:
 * 在执行实际操作时，(Offset + Size) 的总和绝对不能超过对应 MEMORY_DATA_INFORMATION 中的 Size，
 * 否则将触发越界保护机制导致操作失败。
 */
typedef struct _OPERATE_DATA_INFORMATION {
	PVOID DataAddress;  // [in/out] 本地数据缓冲区指针（读操作的接收端 / 写操作的数据源）
	size_t Size;        // [in] 本次操作的数据大小（字节数）
	size_t Offset;      // [in] 相对于内存块基址（OriginalAddress）的偏移量
} OPERATE_DATA_INFORMATION, * POPERATE_DATA_INFORMATION;

/**
 * @brief 单次扫描匹配结果 (Single Scan Match Result)
 *
 * 该结构体用于保存内存扫描中匹配到的单个数据项的完整上下文。
 * 同时记录了目标进程中的真实地址与本地快照中的对应地址，
 * 为后续的“再次扫描过滤”或“直接修改”提供极速的本地操作能力。
 *
 * @note 核心成员:
 * - OriginalAddress: 目标进程中的绝对虚拟地址（用于跨进程写入或校验）。
 * - DataAddress: 本地内存快照中对应数据的指针（用于本地极速比对或读取）。
 */
typedef struct _SCAN_RESULT {
	PVOID OriginalAddress;  // [out] 目标进程中的真实虚拟内存地址
	PVOID DataAddress;      // [out] 本地快照中对应数据的指针
} SCAN_RESULT, * PSCAN_RESULT;

/**
 * @brief 内存扫描结果上下文 (Memory Scan Result Context)
 *
 * 该结构体用于封装单次内存扫描操作（如首次扫描、再次扫描）的最终结果。
 * 它将匹配到的数量与结果列表进行了统一打包，方便函数返回与调用者处理。
 *
 * @note 核心成员:
 * - Count: 扫描到的匹配项总数。
 * - ScanAddress: 指向 SCAN_RESULT 结构体数组的指针。
 *   该数组由函数内部动态分配，包含了所有匹配项的 OriginalAddress 与 DataAddress。
 *
 * @warning 资源管理:
 * ScanAddress 指向的内存是由扫描函数内部动态分配的。
 * 调用者在使用完毕后，必须负责调用 free() 释放该内存，以防止内存泄漏。
 */
typedef struct _TYPE_SCAN {
	size_t Count;           // [out] 扫描到的匹配项数量
	PSCAN_RESULT ScanAddress; // [out] 指向 SCAN_RESULT 数组的指针（需调用者负责 free）
} TYPE_SCAN, * PTYPE_SCAN;

/**
 * @brief 扫描目标进程内存布局 (Scan Process Memory Layout)
 *
 * 该函数通过调用 VirtualQueryEx 遍历目标进程的虚拟地址空间，
 * 动态收集并返回指定范围内所有内存区域（Region）的属性信息。
 *
 * @note 核心步骤:
 * 1. 初始化与分配: 预分配一个 MEMORY_BASIC_INFORMATION 结构体作为初始缓冲区。
 * 2. 步进式探测: 使用 VirtualQueryEx 获取当前地址的内存属性，并以 RegionSize
 *    为步长不断向前推进游标。
 * 3. 安全动态扩容: 采用 (ExecuteCount + 1) 的方式按需 realloc 内存。使用临时
 *    指针接收 realloc 结果，防止返回 NULL 时覆盖原指针导致内存泄漏。
 *
 * @warning 边界防御机制:
 * 循环内设置了双重退出条件以防止死循环和越界：
 * 1. 地址回绕检测 (Address Wrap-around): 当推进后的地址 <= 当前 BaseAddress 时，
 *    说明已触及虚拟内存天花板并发生溢出归零，立即终止。
 * 2. 范围限制: 若用户指定了 ScanSize，当已扫描字节数达到该限制时立即终止。
 *
 * @param hProcess          [in]  目标进程的句柄（需具备 PROCESS_QUERY_INFORMATION 权限）
 * @param ScanMemoryAddress [in]  扫描的起始虚拟内存地址
 * @param ScanSize          [in]  需要扫描的内存大小（若传入 0，则扫描至系统允许的最大地址）
 * @return MEMORY_INFORMATION 包含扫描到的内存信息数组及总字节大小的结构体
 *         - dwSize: 收集到的内存区域总字节数
 *         - MemBasicInfo: 指向动态分配的 MEMORY_BASIC_INFORMATION 数组的指针
 *                         (调用者需负责在使用完毕后调用 free 释放该内存)
 */
MEMORY_INFORMATION ScanMemory(HANDLE hProcess, LPVOID ScanMemoryAddress, size_t ScanSize) {
	// 1. 初始化返回值，防止未初始化的野指针
	MEMORY_INFORMATION result = { 0, nullptr };
	if (hProcess == nullptr) return result;

	size_t ExecuteCount = 0; // 记录当前已经收集到的内存区域数量
	LPVOID CurrentScanAddress = ScanMemoryAddress; // 游标：当前正在探测的内存地址

	// 2. 初始分配：先为 1 个 MEMORY_BASIC_INFORMATION 结构体分配内存
	// 使用 calloc 会自动将内存清零，比 malloc 更安全
	PMEMORY_BASIC_INFORMATION mbi = reinterpret_cast<PMEMORY_BASIC_INFORMATION>(
		calloc(1, sizeof(MEMORY_BASIC_INFORMATION))
	);
	if (mbi == nullptr) return result;

	// 3. 临时变量：用来接收 VirtualQueryEx 每次查询到的结果
	// 为什么不直接查进 mbi 数组里？为了防止越界，必须先查出来，确认安全后再存进去
	MEMORY_BASIC_INFORMATION temp;

	// 4. 核心遍历循环：像扫雷一样，一步步向前推进
	while (true) {
		// 调用系统 API 查询当前地址的内存属性
		size_t RTN = VirtualQueryEx(hProcess, CurrentScanAddress, &temp, sizeof(MEMORY_BASIC_INFORMATION));
		// 如果返回 0，说明查询失败（比如遇到了不可访问的系统保留区，或者已经扫到了尽头）
		if (RTN == 0) break;

		// 5. 动态扩容机制（核心安全防线）
		// 如果当前收集的数量大于等于了已分配的容量（注意：初始分配了1个，所以 ExecuteCount 为 0 时不需要扩容）
		if (ExecuteCount) {
			// 尝试重新分配内存，大小需要容纳 (ExecuteCount + 1) 个结构体
			PMEMORY_BASIC_INFORMATION tempmbi = reinterpret_cast<PMEMORY_BASIC_INFORMATION>(
				realloc(mbi, sizeof(MEMORY_BASIC_INFORMATION) * (ExecuteCount + 1))
			);
			// 【防内存泄漏】：如果 realloc 失败，它会返回 nullptr，但原来的内存还在！
			// 必须先释放原来的 mbi，然后再返回，否则就会造成内存泄漏
			if (tempmbi == nullptr) {
				free(mbi);
				result = { 0, nullptr };
				return result;
			}
			// 扩容成功，把新地址赋给原指针
			mbi = tempmbi;
		}

		// 6. 安全写入：此时内存空间绝对充足，可以放心地把临时数据存入数组
		mbi[ExecuteCount] = temp;
		ExecuteCount++; // 计数器加一

		// 7. 推进游标：当前地址 + 当前内存块的大小 = 下一块内存的起始地址
		CurrentScanAddress = reinterpret_cast<LPVOID>(
			static_cast<char*>(CurrentScanAddress) + temp.RegionSize
		);

		// 8. 边界防御机制（防止死循环和越界）
		// 计算当前已经扫描过的总字节数
		size_t ScannedSize = static_cast<char*>(CurrentScanAddress) - static_cast<char*>(ScanMemoryAddress);

		// 触发退出的两个条件：
		// 条件 A：地址回绕（Address Wrap-around）。如果推进后的地址反而变小了，说明碰到了虚拟内存的天花板，溢出归零了
		// 条件 B：超出用户指定的扫描范围。如果用户限制了 ScanSize，且我们已经扫够了，就立刻收手
		if (CurrentScanAddress <= temp.BaseAddress || (ScanSize > 0 && ScannedSize >= ScanSize)) break;
	};

	// 9. 计算总大小，把数组指针和大小一起返回给调用者
	result.dwSize = ExecuteCount * sizeof(MEMORY_BASIC_INFORMATION);
	result.MemBasicInfo = mbi;
	return result;
}

/**
 * @brief 解析并提取目标进程内存数据 (Parse and Extract Process Memory)
 *
 * 该函数在给定的内存布局信息（MemInfo）中，查找包含指定地址（ParserAddress）的内存区域。
 * 找到后，先进行状态与权限校验（过滤不可访问的 ?? 区域），再通过 ReadProcessMemory
 * 将目标进程中的该段内存安全读取到本地分配的缓冲区中。
 *
 * @note 核心步骤:
 * 1. 区域匹配: 遍历 MemInfo，计算每个 Region 的 [Start, End) 范围，判断目标地址是否落入其中。
 * 2. 防御性校验: 检查目标 Region 的 State 和 Protect 属性，拦截 MEM_FREE 或 PAGE_NOACCESS 的无效地址。
 * 3. 跨进程读取: 在本地分配内存后，调用 ReadProcessMemory 将目标数据“搬运”到本地缓冲区。
 *
 * @warning 资源释放责任:
 * 若函数成功返回（DataAddress 不为 nullptr），调用者在使用完毕后，必须负责调用
 * VirtualFree 释放该内存，否则会导致本地内存泄漏。
 *
 * @param hProcess      [in]  目标进程的句柄（需具备 PROCESS_VM_READ 权限）
 * @param MemInfo       [in]  由 ScanMemory 获取的内存布局信息结构体
 * @param ParserAddress [in]  需要在目标进程中提取数据的起始虚拟地址
 * @param ParserSize    [in]  需要提取的内存数据大小（字节数）
 * @return MEMORY_DATA_INFORMATION 包含原始地址、本地数据缓冲区指针及大小的结构体
 *         - OriginalAddress: 目标进程中的原始地址
 *         - DataAddress: 本地分配的缓冲区指针（若为 nullptr 则表示地址无效或读取失败）
 *         - Size: 成功读取的字节数
 */
MEMORY_DATA_INFORMATION ParserMemory(HANDLE hProcess, MEMORY_INFORMATION MemInfo, PVOID ParserAddress, size_t ParserSize) {
	MEMORY_DATA_INFORMATION result = { nullptr, nullptr, 0 };
	if (hProcess == nullptr || ParserSize == 0) return result;

	size_t Count = MemInfo.dwSize / sizeof(MEMORY_BASIC_INFORMATION);
	PMEMORY_BASIC_INFORMATION pMBI = MemInfo.MemBasicInfo;

	for (size_t Index = 0; Index < Count; Index++) {
		PVOID StartAddress = pMBI[Index].BaseAddress;
		// 结束地址必须是 起始地址 + 区域大小
		PVOID EndAddress = static_cast<char*>(StartAddress) + pMBI[Index].RegionSize;

		// 判断目标地址是否在当前 Region 的范围内 [Start, End)
		if (StartAddress <= ParserAddress && ParserAddress < EndAddress) {
			// 在匹配到目标 Region 后，读取前进行防御性检查
			if (pMBI[Index].State == MEM_FREE || (pMBI[Index].Protect & PAGE_NOACCESS)) {
				// 这是一个未分配或不可访问的地址，相当于 CE 里的 ??
				result.OriginalAddress = ParserAddress;
				return result; 
			}
			// 在本地分配内存，用于接收数据
			void* AllocateAddress = VirtualAlloc(NULL, ParserSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (AllocateAddress == nullptr) return result;

			size_t ReadBytes = 0;
			// 使用 ReadProcessMemory 从目标进程读取数据到本地
			BOOL rtn = ReadProcessMemory(hProcess, ParserAddress, AllocateAddress, ParserSize, &ReadBytes);

			if (rtn && ReadBytes == ParserSize) {
				// 读取成功，打包结果
				result.OriginalAddress = ParserAddress;
				result.DataAddress = AllocateAddress;
				result.Size = ReadBytes;
				return result;
			}
			else {
				// 读取失败，必须释放刚才分配的内存，防止泄漏
				VirtualFree(AllocateAddress, 0, MEM_RELEASE);
				return result;
			}
		}
	}
	// 遍历结束未找到，必须兜底返回空结果
	return result;
}

/**
 * @brief 向目标进程内存写入数据并回读校验 (Write and Verify Memory)
 *
 * 该函数将本地缓冲区的数据写入目标进程的指定偏移位置。
 * 写入成功后，会立即回读目标进程中刚刚修改的对应内存区域，
 * 以验证写入操作是否真正生效，并同步更新本地内存快照。
 *
 * @note 核心步骤:
 * 1. 参数防御: 严格校验句柄、指针及数据大小的有效性，拦截非法输入。
 * 2. 越界保护: 计算实际写入位置，校验 (Offset + Size) 是否超出原始内存块边界，防止引发目标进程崩溃。
 * 3. 跨进程写入: 调用 WriteProcessMemory 将本地数据注入目标进程。
 * 4. 精准回读校验: 仅回读本次修改的精确范围（而非整个内存块），验证写入结果并更新本地 DataAddress 中的对应数据。
 *
 * @warning 越界保护机制:
 * 若传入的 OperateData.Offset + OperateData.Size 大于 mdi.Size，
 * 函数将直接返回 false 拒绝执行，以避免内存越界写入导致目标进程异常。
 *
 * @param hProcess      [in]  目标进程的句柄（需具备 PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ 权限）
 * @param mdi           [in/out] 由 ParserMemory 获取的原始内存数据信息。
 *                      若写入并回读成功，函数会同步更新 mdi.DataAddress 中对应偏移量的本地数据。
 * @param OperateData   [in]  包含要写入的本地数据、大小及目标偏移量的结构体
 * @return bool         写入并回读校验均成功返回 true，任意环节失败返回 false
 */
bool WriteMemory(HANDLE hProcess, MEMORY_DATA_INFORMATION mdi, OPERATE_DATA_INFORMATION OperateData) {
	// 1. 参数防御性校验
	if (hProcess == nullptr ||
		mdi.OriginalAddress == nullptr ||
		mdi.DataAddress == nullptr ||
		mdi.Size == 0 ||
		OperateData.DataAddress == nullptr ||
		OperateData.Size == 0) {
		return false;
	}

	// 2. 计算实际写入位置
	// 目标进程中的绝对写入地址 = 原始内存块基址 + 块内偏移量
	LPVOID OperatePos = nullptr;
	OperatePos = static_cast<char*>(mdi.OriginalAddress) + OperateData.Offset;

	// 【越界保护】：核心安全防线
	// 必须确保“偏移量 + 写入大小”没有超出当前内存快照（mdi.Size）的范围。
	// 如果越界，不仅会破坏目标进程的其他数据，还可能导致目标程序直接崩溃。
	if (OperateData.Offset + OperateData.Size > mdi.Size) return false;

	// 3. 执行跨进程写入
	// 将本地缓冲区（OperateData.DataAddress）的数据，注入到目标进程的指定位置（OperatePos）
	size_t OperateBytes = 0;
	BOOL rtn = WriteProcessMemory(hProcess, OperatePos, OperateData.DataAddress, OperateData.Size, &OperateBytes);

	// 写入失败，或者实际写入的字节数与期望不符，说明操作未完全生效，直接返回 false
	if (!rtn || OperateBytes != OperateData.Size) return false;

	// 4. 精准回读与本地快照同步
	// 计算本地内存快照中对应的偏移位置
	LPVOID LocalPos = static_cast<char*>(mdi.DataAddress) + OperateData.Offset;

	// 为什么写入后还要立刻回读？
	// 1. 验证写入是否真的生效（防止被反作弊系统拦截或内存只读属性导致写入假成功）。
	// 2. 同步更新本地快照：因为我们之前是“整块读取”建立的内存快照，修改后必须把最新的值同步回本地，
	//    这样后续在本地分析这块内存时，数据才是自洽且一致的。
	rtn = ReadProcessMemory(hProcess, OperatePos, LocalPos, OperateData.Size, &OperateBytes);

	// 回读失败或读取不完整，说明目标内存状态已发生不可控变化，返回 false
	if (!rtn || OperateBytes != OperateData.Size) return false;

	// 写入并校验成功
	return true;
}
/**
 * @brief 从目标进程读取指定偏移的内存数据 (Read Memory from Target Process)
 *
 * 该函数在目标进程中，基于原始内存块的基址和给定的偏移量，
 * 读取指定大小的数据到本地缓冲区中。
 *
 * @note 核心步骤:
 * 1. 参数防御: 严格校验句柄、指针及数据大小的有效性。
 * 2. 越界保护: 校验 (Offset + Size) 是否超出原始内存块边界，防止越界读取。
 * 3. 跨进程读取: 调用 ReadProcessMemory 将目标进程的数据拉取到本地缓冲区。
 *
 * @warning 越界保护机制:
 * 若传入的 OperateData.Offset + OperateData.Size 大于 mdi.Size，
 * 函数将直接返回 false 拒绝执行，以防止读取到目标进程的其他无关内存区域。
 *
 * @param hProcess      [in]  目标进程的句柄（需具备 PROCESS_VM_READ 权限）
 * @param mdi           [in]  由 ParserMemory 获取的原始内存数据信息
 * @param OperateData   [in/out] 包含目标偏移量及本地接收缓冲区的结构体
 * @return bool         读取成功返回 true，任意环节失败返回 false
 */
bool ReadMemory(HANDLE hProcess, MEMORY_DATA_INFORMATION mdi, OPERATE_DATA_INFORMATION OperateData) {
	// 1. 参数防御性校验
	if (hProcess == nullptr ||
		mdi.OriginalAddress == nullptr ||
		mdi.DataAddress == nullptr ||
		mdi.Size == 0 ||
		OperateData.DataAddress == nullptr ||
		OperateData.Size == 0) {
		return false;
	}

	// 2. 计算实际读取位置
	LPVOID OperatePos = static_cast<char*>(mdi.OriginalAddress) + OperateData.Offset;

	// 【核心修复】：越界保护！确保读取的终点没有超出原始内存块的范围
	if (OperateData.Offset + OperateData.Size > mdi.Size) return false;

	// 3. 执行跨进程读取
	size_t ReadBytes = 0;
	BOOL rtn = ReadProcessMemory(hProcess, OperatePos, OperateData.DataAddress, OperateData.Size, &ReadBytes);
	if (!rtn || ReadBytes != OperateData.Size) return false;

	return true;
}

/**
 * @brief 基于本地快照的首次内存值扫描 (First Memory Value Scan based on Local Snapshot)
 *
 * 该函数是一个模板函数，用于在指定的本地内存快照（mdi.DataAddress）中，
 * 遍历查找所有等于指定值（Value）的数据。找到后，将其对应的目标进程绝对地址
 * 动态存入结果列表中。这是实现类似 Cheat Engine “首次扫描”功能的核心底层逻辑。
 *
 * @note 核心步骤:
 * 1. 边界防御: 严格校验快照指针及大小，循环内通过 (CurrentAddress + sizeof(Type) <= EndAddress)
 *    防止尾部越界读取。
 * 2. 内存快照比对: 在本地内存中按 Type 类型的大小步进遍历，避免跨进程系统调用，实现极速扫描。
 * 3. 动态结果收集: 使用 realloc 动态扩容地址列表，将匹配到的本地偏移量转换为
 *    目标进程的真实虚拟地址（OriginalAddress + Offset）并保存。
 *
 * @warning 资源释放责任:
 * 若扫描成功（Count > 0），result.ScanAddress 指向一块由 realloc 动态分配的内存。
 * 调用者在使用完毕后，必须负责调用 free() 释放该内存，否则会导致内存泄漏。
 *
 * @tparam Type            要扫描的数据类型（如 int, float, double 等）
 * @param mdi           [in]  由 ParserMemory 获取的原始内存数据信息（包含本地快照及目标基址）
 * @param Value         [in]  需要在内存中查找的目标值
 * @return TYPE_SCAN    包含匹配结果数量及目标进程地址列表的结构体
 *         - Count: 找到的匹配项总数
 *         - ScanAddress: 指向目标进程绝对地址列表的指针（需调用者负责 free 释放）
 */
template <typename Type>
TYPE_SCAN ScanTypeValueByMDI(MEMORY_DATA_INFORMATION mdi, void* Value) {
	TYPE_SCAN result = { 0, nullptr };

	// 1. 参数防御性校验，获取扫描数值
	if (mdi.OriginalAddress == nullptr ||
		mdi.DataAddress == nullptr ||
		mdi.Size == 0) {
		return result;
	}
	Type RealValue = *static_cast<Type*>(Value);
	
	// 2. 初始化扫描环境
	// 我们不需要预先分配内存，因为我们还不知道能找到多少个结果。
	// 先让指针为空，等找到第一个结果时再分配。
	size_t Count = 0;
	PSCAN_RESULT AddressList = nullptr;

	// 计算扫描的终点：本地快照基址 + 快照总大小
	// 注意：EndAddress 应该是 char* 类型，方便进行字节级的指针运算
	char* EndAddress = static_cast<char*>(mdi.DataAddress) + mdi.Size;

	// CurrentAddress 是游标，从快照的起始位置开始
	// 为了支持任意类型 Type (如 int, float, double)，我们需要按 Type 的大小步进
	// 所以这里强转为 Type* 类型
	Type* CurrentAddress = static_cast<Type*>(mdi.DataAddress);

	// 3. 核心扫描循环
	// 只要游标还没走到终点，就继续找
	// 注意：为了防止越界读取，循环条件必须确保剩下的空间足够放下一个 Type 类型的数据
	while (reinterpret_cast<char*>(CurrentAddress) + sizeof(Type) <= EndAddress) {

		// 【兼容性优化】：使用 memcmp 进行二进制级别比对，完美兼容 float/double 精度问题
		if (memcmp(CurrentAddress, Value, sizeof(Type)) == 0) {

			Count++;

			// 【动态数组扩容】：这是最关键的步骤
			// 每次找到新结果，都需要重新分配内存来存储这个新地址
			// 使用 realloc 在原有内存基础上扩容
			PSCAN_RESULT TempList = static_cast<PSCAN_RESULT>(realloc(AddressList, Count * sizeof(SCAN_RESULT)));

			if (TempList == nullptr) {
				// 内存分配失败，清理现场并返回
				free(AddressList);
				return result;
			}

			// 更新指针
			AddressList = TempList;

			// 将当前找到的【目标进程中的绝对地址】存入列表
			// 计算公式：原始基址 + (当前本地指针 - 本地基址)
			// 这样可以算出这个值在目标进程里的真实地址
			size_t Offset = reinterpret_cast<char*>(CurrentAddress) - static_cast<char*>(mdi.DataAddress);
			AddressList[Count - 1].OriginalAddress = reinterpret_cast<char*>(mdi.OriginalAddress) + Offset;
			AddressList[Count - 1].DataAddress = CurrentAddress;
		}

		// 4. 移动游标
		// 指针自动加 1，对于 Type* 类型的指针，这意味着地址向后移动 sizeof(Type) 个字节
		CurrentAddress++;
	}

	// 5. 封装结果
	result.Count = Count;
	result.ScanAddress = AddressList; // 返回找到的地址列表

	return result;
}

/**
 * @brief 基于已有结果集的内存值过滤扫描 (Filter Scan based on Existing Result Set)
 *
 * 该函数用于内存扫描的“再次扫描（过滤）”阶段。
 * 它遍历上一次扫描留下的结果集（TypeScanArea），在本地快照中重新比对数据，
 * 剔除不再匹配的值，从而大幅缩小目标地址的范围。
 *
 * @note 核心步骤:
 * 1. 结果集遍历: 遍历传入的 TypeScanArea，获取每个候选地址的本地快照指针（DataAddress）。
 * 2. 二进制比对: 使用 memcmp 进行严格的二进制比对，完美兼容 float/double 等类型的过滤。
 * 3. 动态结果收集: 采用“容量翻倍”策略动态扩容，将匹配到的 SCAN_RESULT 整体拷贝到新列表中。
 *
 * @warning 资源释放责任:
 * 过滤成功后，返回的 result.ScanAddress 是一块全新的内存。
 * 调用者在使用新结果后，必须负责调用 free() 释放旧的 TypeScanArea.ScanAddress，
 * 否则会导致严重的内存泄漏！
 *
 * @tparam Type            要扫描的数据类型（如 int, float, double 等）
 * @param TypeScanArea  [in]  上一次扫描（或过滤）留下的结果集
 * @param Value         [in]  需要在内存中重新查找/过滤的目标值
 * @return TYPE_SCAN    包含过滤后的匹配结果数量及新地址列表的结构体
 */
template <typename Type>
TYPE_SCAN ScanTypeValueByArea(TYPE_SCAN TypeScanArea, void* Value) {
	TYPE_SCAN result = { 0, nullptr };

	// 1. 参数防御性校验，获取扫描数值
	if (TypeScanArea.Count == 0 ||
		TypeScanArea.ScanAddress == nullptr) {
		return result;
	}
	Type RealValue = *static_cast<Type*>(Value);

	// 2. 初始化扫描环境
	// 我们不需要预先分配内存，因为我们还不知道能找到多少个结果。
	// 先让指针为空，等找到第一个结果时再分配。
	size_t Count = 0;
	PSCAN_RESULT OriginalList = TypeScanArea.ScanAddress;
	PSCAN_RESULT AddressList = nullptr;

	// 3. 核心扫描循环
	for (size_t Index = 0; Index < TypeScanArea.Count; Index++) {

		// 【兼容性优化】：使用 memcmp 进行二进制级别比对，完美兼容 float/double 精度问题
		if (memcmp(OriginalList[Index]->DataAddress, Value, sizeof(Type)) == 0) {

			Count++;

			// 【动态数组扩容】：这是最关键的步骤
			// 每次找到新结果，都需要重新分配内存来存储这个新地址
			// 使用 realloc 在原有内存基础上扩容
			PSCAN_RESULT TempList = static_cast<PSCAN_RESULT>(realloc(AddressList, Count * sizeof(SCAN_RESULT)));

			if (TempList == nullptr) {
				// 内存分配失败，清理现场并返回
				free(AddressList);
				return result;
			}

			// 更新指针
			AddressList = TempList;
			AddressList[Count - 1] = OriginalList[Index];
		}
	}

	// 4. 封装结果
	result.Count = Count;
	result.ScanAddress = AddressList; // 返回找到的地址列表

	return result;
}

typedef SCAN_RESULT(*ScanByMDI)(MEMORY_DATA_INFORMATION mdi, void* Value);
typedef SCAN_RESULT(*ScanByArea)(TYPE_SCAN TypeScanArea, void* Value);

typedef struct _PROCESS_ENTRY_INFO {
	DWORD ProcessID;
	wchar_t ProcessName[256];
} PROCESS_ENTRY_INFO, *PPROCESS_ENTRY_INFO;

PROCESS_ENTRY_INFO CurrentProcessInfo = { 0, L"" };

bool FindAndPrintProcess(PROCESSENTRY32* ProcessList, DWORD Count, PROCESS_ENTRY_INFO& ProcessInfo, const wchar_t* targetName = nullptr, DWORD targetPid = 0) {
	bool rtn = false; 
	for (DWORD i = 0; i < Count; i++) {
		bool match = false;
		if (targetName != nullptr) {
			match = (wcscmp(ProcessList[i].szExeFile, targetName) == 0);
		}
		else {
			match = (ProcessList[i].th32ProcessID == targetPid);
		}

		if (match) {
			wprintf(L"find Process: PID=%u, Name=%s\n", ProcessList[i].th32ProcessID, ProcessList[i].szExeFile);
			if (targetName == nullptr) {
				ProcessInfo.ProcessID = ProcessList[i].th32ProcessID;
				wcscpy_s(ProcessInfo.ProcessName, 256, ProcessList[i].szExeFile);
				return true;
			}else {
				rtn = true;
			}
		}
	}
	return rtn;
}

void ScanProcess() {
	// 扫描进程的逻辑
	DWORD Count = 0;
	PROCESSENTRY32* ProcessList = nullptr;
	ProcessList = GetProcessEntryInfo(Count);
	PrintProcessEntryInfo(ProcessList, Count);
	printf("\n扫描到的进程数量: %d\n", Count);

	// 1. 添加菜单提示并接收用户选择
	printf("请选择扫描方式:\n");
	printf("/n - 按进程名扫描\n");
	printf("/p - 按PID扫描\n");
	
	bool Flag = false;
	wchar_t cmd[3] = { 0 };
	wchar_t target[256] = { 0 };
	wscanf_s(L"%s %s", cmd, (unsigned)_countof(cmd), target, (unsigned)_countof(target)); // 读取用户的选择
	switch (cmd[1]) {
		case 'n': {
			// 按进程名扫描
			wchar_t targetName[256];
			wcscpy_s(targetName, 256, target); // 默认扫描 notepad.exe
			if (FindAndPrintProcess(ProcessList, Count, CurrentProcessInfo, targetName)) {
				printf("选择指定进程 PID: ");
				DWORD targetPid = 0;
				scanf_s("%u", &targetPid);
				Flag = FindAndPrintProcess(ProcessList, Count, CurrentProcessInfo, nullptr, targetPid);
			}
			break;
		}
		case 'p': {
			// 按PID扫描
			DWORD targetPid = _wtoi(target);
			Flag = FindAndPrintProcess(ProcessList, Count, CurrentProcessInfo, nullptr, targetPid);
			break;
		}
	}
	if(CurrentProcessInfo.ProcessID) {
		printf("当前扫描的进程PID: %u\n", CurrentProcessInfo.ProcessID);
	}
	else {
		printf("未找到指定进程。\n");
	}
}

void ScanProcessValue() {
	// 扫描指定值的逻辑
	void* ProcessBaseAddress = GetModuleBaseAddress(CurrentProcessInfo.ProcessID, CurrentProcessInfo.ProcessName);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, CurrentProcessInfo.ProcessID);
	if (hProcess == nullptr) {
		printf("[错误] 无法打开目标进程，请确保以管理员身份运行程序！\n");
		return;
	}
	MEMORY_INFORMATION memInfo = ScanMemory(hProcess, ProcessBaseAddress, 0x2000);
	MEMORY_DATA_INFORMATION mdi = { 0 };
	PVOID ProcessTextBase = static_cast<char*>(ProcessBaseAddress) + 0x1000;
	mdi = ParserMemory(hProcess, memInfo, ProcessTextBase, 0x10000);
	if (mdi.DataAddress == nullptr) {
		printf("[错误] 本地内存分配失败！\n");
		CloseHandle(hProcess);
		return;
	}

	void* ProcessDataBase = mdi.OriginalAddress;
	void* ProcessDataAddress = mdi.DataAddress;
	size_t Size = mdi.Size;
	if (Size) {
		for (size_t i = 0; i < Size; i += 16) {
			printf("%016llX | ", (uintptr_t)((char*)ProcessDataBase + i));
			for (DWORD j = 0; j < 16; j++) {
				unsigned char Byte = *(unsigned char*)((char*)ProcessDataAddress + i + j);
				printf("%02X ", Byte);
			}
			printf("| ");
			for (DWORD j = 0; j < 16; j++) {
				unsigned char Byte = *(unsigned char*)((char*)ProcessDataAddress + i + j);
				printf("%c", (Byte >= 32 && Byte <= 126) ? Byte : '.');
			}
			printf("\n");
		}
	}
	else {
		// 3. 读取内存失败（可能是基址不对，或者被反作弊拦截）
		printf("[错误] 内存读取失败！读取字节数: %zu\n", Size);
	}

	// 4. 正常执行完毕的提示
	printf("\n[完成] 内存读取与打印结束。\n");

	char tmp = 40;
	TYPE_SCAN TypeScanResult = ScanTypeValueByMDI<char>(mdi, &tmp);
	
	PSCAN_RESULT ScanResult = TypeScanResult.ScanAddress;
	for (size_t Index = 0; Index < TypeScanResult.Count; Index++) {
		printf("%p\t%d\n", ScanResult[Index].OriginalAddress, *(char*)ScanResult[Index].DataAddress);
	}
	free(ScanResult);
	CloseHandle(hProcess);
	VirtualFree(mdi.DataAddress, 0, MEM_RELEASE);
}


int main() {
	ScanProcess();
	ScanProcessValue();
	return 0;
}
