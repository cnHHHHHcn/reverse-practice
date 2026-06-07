/**
 * @file StackHijack.cpp
 * @brief x86 栈返回地址劫持与 Shellcode + ROP 注入实验
 *
 * @details
 * 本文件演示了通过直接修改函数栈帧中的返回地址（Return Address），
 * 实现程序执行流（EIP/RIP）劫持的核心技术。
 * 核心机制包括：
 * 1. 【栈地址推算】：利用函数参数地址反推栈上返回地址的物理位置。
 * 2. 【内存读写原语】：使用 memcpy 构造任意地址读写（ARW），备份原返回地址。
 * 3. 【混合式利用 (Hybrid Exploit)】：
 *		- 利用 ROP 链（Push + Ret）模拟 call 调用约束并触发 MessageBoxA
 *		- 结合 Shellcode 注入实现函数返回值(EAX)篡改与流恢复。
 * 4. 【控制流恢复】：在 Shellcode 中动态修补原返回地址并执行 ret，维持程序稳定性。
 *
 * 【技术特征 / Technical Notes】
 * 1. **栈帧布局依赖** (参考 StackView.cpp)：
 *	  - 本示例假设 x86 栈帧布局为 [返回地址][EBP][参数1]，因此通过参数地址减偏移量获取返回地址。
 *	  - 该布局在 x86 编译器中较为常见，但在 x64 或开启优化的情况下可能不适用。
 * 2. ** x86汇编指令解析、调用约定适配** (参考 AsmNote.txt)：
 *    - 深层解析并理解 push、pop、ret 等指令。
 *    - 默认使用 _cdecl，需注意劫持后栈平衡的维护（Shellcode 中需清理 push 的数据）。
 *    - 若使用 _stdcall，需确保被劫持函数的参数清理不会破坏 Shellcode 布局。
 * 3. **硬编码偏移风险**：
 *    - 代码中 ((char*)&Num1 - 8) 强依赖 x86 栈帧布局（[RetAddr][EBP][Num1]）。
 *    - 开启编译器优化（如 /O2）或更改函数签名可能导致偏移量失效。
 * 4. **防御绕过**：
 *	  - 必须编译 Release x86
 *    - 必须关闭 /GS 缓冲区安全检查，否则栈 Cookie 会阻止返回地址被直接覆盖。
 *    - 必须关闭编译器优化（/Od），防止内联汇编或参数寄存器传递破坏栈推算逻辑。
 *
 * @warning
 * 本代码涉及栈溢出/篡改等未定义行为，仅用于安全研究与逆向工程教学。
 * 严禁在生产环境或任何未经授权的系统中使用此类技术。
 *
 *  Let's Debug!
 *    -> 操作路径: Visual Studio [调试] -> [反汇编] (Disassembly) + [内存] (Memory)
 *    -> 目标：
 *       1. 【见证劫持时刻】：在 Add 函数末尾，观察栈内存窗口。
 *          确认原本指向 main 的返回地址已被替换为 ShellcodeAddress。
 *       2. 【追踪 Shellcode 执行】：单步执行 ret 指令。
 *          观察 EIP/RIP 寄存器是否跳转至 Shellcode 区域，触发 MessageBoxA 并验证 EAX 寄存器是否被修改为 32。
 *       3. 【验证恢复逻辑】：在 Shellcode 的 ret 指令后，确认程序流是否正确返回 main 继续执行。
 *
 * @author cnHHHHHcn
 * @date 2026-06-07
 * @version 1.1 (Experimental - Stack Control Flow Hijacking)
 */

// 编译 Release x86
// 关闭编译器优化：
// 项目配置属性 -> C/C++ -> 优化(已禁用(/Od))
// 关闭 GS 安全检查：
// 在项目属性中，找到 C / C++->代码生成->安全检查，将其设置为 禁用安全检查(/ GS - )。

/**
 * Tips - 编译器优化
 * 如果函数内没有用到形参，则传入寄存器
 */

#include <windows.h>
#include <iostream>

 // 劫持成功后 MessageBoxA 的标题和内容
const char* HackedTitle = "Stack hijack";
const char* HackedPropmt = "I hijacked the Add function, tampered with its return address, and successfully triggered MessageBoxA.";

void* HaijackStackAddress = nullptr;	// 需要劫持的栈地址
void* ReturnAddress = nullptr;			// 原返回地址
void* ShellcodeAddress = nullptr;		// shellcode地址
// 栈数据关系: HaijackStackAddress -> ReturnAddress 

/**
 * Flow Overview:
 *  Original flow: main() -> Add() -> return to main()
 *  Hijacked flow: main() -> Add() -> 恶意shellcode -> User32.dll!MessageBoxA -> 恶意shellcode -> return to main()
 * 
 *  注：_cdecl和_stdcall的区别在于栈清理方式，但对于本示例中的劫持原理没有影响。
 *	   因为我们直接修改了返回地址，无论使用哪种调用约定，都会劫持到shellcode执行。
 */

int _stdcall /* _cdecl(默认) | _stdcall */ Add(int Num1, int Num2) {
	
	// 通过获取Num1的地址，获取 返回地址 的栈地址(HaijackStackAddress)
	HaijackStackAddress = &Num1;
	HaijackStackAddress = ((char*)HaijackStackAddress - sizeof(Num1));
	
	// 保存返回地址(ReturnAddress)，以便 恶意shellcode 执行完后能正确返回到main函数继续执行
	ReturnAddress = *(void**)HaijackStackAddress;		
	memcpy(((char*)ShellcodeAddress + 34), &ReturnAddress, 4);
	
	// 将shellcode地址写入返回地址，劫持程序流
	memcpy(HaijackStackAddress, &ShellcodeAddress, 4);

	return Num1 + Num2;
}

int main() {
	// 恶意shellcode功能: 调用MessageBoxA，参数为 (NULL, HackedPropmt, HackedTitle, MB_OK | MB_ICONINFORMATION)，并将EAX寄存器(返回值)修改为32
	// 注：在shellcode汇编指令中的 5 - 7 行的指令模拟了 call MessageBoxA 的行为，手动压入参数并通过 ret 触发调用，实现控制流重定向。
	// 如果不理解可以参考 AsmNote.txt x86汇编指令解析
	unsigned char shellcode[] = {
		0x68, 0x40, 0x00, 0x00, 0x00,		// push 0x00000040 (MB_OK | MB_ICONINFORMATION)
		0x68, 0x00, 0x00, 0x00, 0x00,		// push 0x00000000 (HackedTitle Address)
		0x68, 0x00, 0x00, 0x00, 0x00,		// push 0x00000000 (HackedPrompt Address)
		0x6A, 0x00,							// push 0 (NULL)
		0x68, 0x00, 0x00, 0x00, 0x00,		// push 0x00000000 (Return Address = shellcode Address + 28 => [mov eax, 32])
		0x68, 0x00, 0x00, 0x00, 0x00,		// push 0x00000000 (MessageBoxA Address)
		0xC3,								// ret
		0xB8, 0x20, 0x00, 0x00, 0x00,		// mov eax, 32
		0x68, 0x00, 0x00, 0x00, 0x00,		// push 0x00000000 (ReturnAddress)
		0xC3								// ret
	};

	// 修改内存权限，使shellcode可执行
	DWORD oldProtect;
	ShellcodeAddress = shellcode;
	VirtualProtect(shellcode, sizeof(shellcode), PAGE_EXECUTE_READWRITE, &oldProtect);
	
	// 填充shellcode中的地址
	memcpy(((char*)shellcode + 6), &HackedTitle, 4);					// shellcode中push的 第二个参数地址
	memcpy(((char*)shellcode + 11), &HackedPropmt, 4);					// shellcode中push的 第三个参数地址
	void* ReturnAddressForShellcode = ((char*)ShellcodeAddress + 28);	// shellcode中push的 返回地址，指向shellcode中mov eax, 32的指令
	memcpy(((char*)shellcode + 18), &ReturnAddressForShellcode, 4);		// shellcode中push的 第四个参数地址
	HMODULE hUser32 = LoadLibraryA("user32.dll");
	if(hUser32 == NULL) {
		std::cerr << "Failed to load user32.dll" << std::endl;
		return -1;
	}
	FARPROC pMsgBox = GetProcAddress(hUser32, "MessageBoxA");
	if(pMsgBox == NULL) {
		std::cerr << "Failed to get MessageBoxA address" << std::endl;
		FreeLibrary(hUser32);
		return -1;
	}
	memcpy(((char*)shellcode + 23), &pMsgBox, 4);					// shellcode中push的 MessageBoxA 地址
	
	// 调用Add函数，触发劫持
	int a = 1, b = 2;
	int c = Add(a, b);

	// 输出结果，应该输出32，而不是3
	std::cout << c;
	FreeLibrary(hUser32);
	return 0;
}