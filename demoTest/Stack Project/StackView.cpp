/**
 * @file StackView.cpp
 * @brief x86 平台栈帧布局深度解析与逆向工程辅助工具
 *
 * @details
 * 本文件通过精心设计的内存地址推算与指针偏移操作，
 * 详细展示了 C++ 函数调用过程中栈帧（Stack Frame）的物理内存布局。
 * 核心机制包括：
 * 1. 【栈地址推算】：利用已知局部变量地址，通过偏移量反推参数、返回地址及基址指针（EBP）。
 * 2. 【内存取证】：直接读取并打印栈上特定位置的数据，揭示传值与传引用的区别。
 * 3. 【结构体布局分析】：演示结构体作为参数（值传递）时在栈上的展开方式。
 * 4. 【调用约定验证】：基于 _cdecl | _stdcall 约定，验证参数由右至左入栈及栈清理责任方。
 *
 * 【技术特征 / Technical Notes】
 * 1. **编译器依赖性**：
 *    - 必须关闭编译器优化（/Od），防止内联或寄存器变量干扰栈布局。
 *    - 代码中的偏移量（如 sizeof(void*) * 2）强依赖 x86 调用约定和 MSVC 编译器的栈帧结构。
 * 2. **参数传递机制**：
 *    - 值传递（StructParam）会导致整个结构体按字节复制到栈上，造成较大的内存开销。
 *    - 引用传递（StructParam&）在栈上仅表现为一个指针（通常 4 字节），指向实参的原始内存。
 * 3. **栈生长方向**：
 *    - 代码通过地址比较直观展示了 x86 架构下栈从高内存地址向低内存地址生长的特性。
 *    - 局部变量的排列顺序受内存对齐（Padding）和编译器优化策略影响，并非绝对固定。
 *
 * @warning
 * 本代码涉及直接内存读写和指针算术运算，属于未定义行为（UB）的边缘探索。
 * 仅用于教学演示和逆向工程原理研究，严禁在生产环境或安全敏感代码中使用。
 *
 *  Let's Debug!
 *    -> 操作路径: Visual Studio [调试] -> [内存] (Memory) + [反汇编] (Disassembly)
 *    -> 目标：
 *       1. 【验证偏移逻辑】：在 Func 函数内部，对比 &Num2、&Num1 与推算出的 Return Address 地址。
 *          确认偏移量计算 (pTest - 2*sizeof(void*)) 是否准确指向返回地址。
 *       2. 【观察结构体传递】：尝试修改 Func 参数将 StructParam 改为 const StructParam&。
 *          观察栈上 Param 的地址是否变为 4 字节指针，并验证其指向是否与 main 中的 Param 一致。
 *       3. 【追踪 EBP 链】：通过打印出的 "Main Stack Base Point"，在内存窗口中查看 EBP 寄存器链表，
 *          理解函数调用栈的回溯（Backtrace）原理。
 *
 * @author cnHHHHHcn
 * @date 2026-06-02
 * @version 1.0 (Educational - Stack Frame Layout Analysis)
 */

// 编译 Release x86
// 关闭编译器优化：
// 项目配置属性 -> C/C++ -> 优化(已禁用(/Od))
/**
 * Tips - 编译器优化
 * 如果函数内没有用到形参，则传入寄存器
 */

#include <iostream>

struct StructParam {
	int Param1;
	int Param2;
	int result;
};

// try: 试试给第三个参数类型 StructParam 改为 StructParam&，看看栈布局和参数传递方式有什么变化。
//		理解引用参数在栈上的表现，以及它与值传递的区别。
int /*_cdecl(默认) | _stdcall*/ Func(int Num1, int Num2, StructParam Param) {
	void* pTest = &Num2;
	void* Buffer = ((char*)pTest - sizeof(void*) * 2);
	std::cout << "\n------------------------------------------------\nCalled Func\n";
	std::cout << "pTest Stack Address:0x" << &pTest << '\n';
	std::cout << "Buffer Stack Address:0x" << &Buffer << '\n';
	std::cout << "Num1 Stack Address:0x" << &Num1 << "\tValue:" << *(int*)((char*)pTest - sizeof(void*)) << '\n';
	std::cout << "Num2 Stack Address:0x" << &Num2 << "\tValue:" << *(int*)pTest << "\n\n";
	
	Param.result = Param.Param1 + Param.Param2;
	std::cout << "Param Stack Address:0x" << &Param << '\n';
	std::cout << "Param.Param1 Stack Address:0x" << &Param.Param1 << "\tValue:" << Param.Param1 << '\n';
	std::cout << "Param.Param2 Stack Address:0x" << &Param.Param2 << "\tValue:" << Param.Param2 << '\n';
	std::cout << "Param.result Stack Address:0x" << &Param.result << "\tValue:" << Param.result << "\n\n";
	std::cout << "Return Asm Code Address:0x" << std::hex << Buffer << "\tValue:0x" << *(void**)Buffer << '\n';
	
	Buffer = ((char*)pTest - sizeof(void*) * 3);
	std::cout << "Main Stack Base Point:0x" << Buffer << "\tValue:0x" << *(void**)Buffer << '\n' << std::dec;
	std::cout << "return main" << "\n------------------------------------------------\n";

	return Num1 + Num2;
}

int main(){
	std::cout << "Called main";
	int Num1 = 10;
	int Num2 = 20;
	StructParam Param = { 30, 20, 0 };
	int TestResult = Func(Num1, Num2, Param);

	std::cout << "Num1 Stack Address:0x" << &Num1 << "\tValue:" << Num1 << '\n';
	std::cout << "Num2 Stack Address:0x" << &Num2 << "\tValue:" << Num2 << "\n\n";
	std::cout << "Param Stack Address:0x" << &Param << '\n';
	std::cout << "Param.Param1 Stack Address:0x" << &Param.Param1 << "\tValue:" << Param.Param1 << '\n';
	std::cout << "Param.Param2 Stack Address:0x" << &Param.Param2 << "\tValue:" << Param.Param2 << '\n';
	std::cout << "Param.result Stack Address:0x" << &Param.result << "\tValue:" << Param.result << "\n\n";
	std::cout << "TestResult Stack Address:0x" << &TestResult << "\n\n\n";
	
	// 获取 main 和 Func 的地址
	std::cout << "Function Address Overview:" << '\n';
	std::cout << "main Address:0x" << main << '\n';
	std::cout << "Func Address:0x" << Func << std::endl;
	return 0;
}

// Stack Layout (x86, cdecl calling convention):
// (视角：从低地址 -> 高地址，基于真实打印数据还原)

// Low Address (栈顶方向)
// ----------------------------
// [Func 的局部变量]
// pTest                <-- (Func 内部: void* pTest = &Num2;)
// Buffer               <-- (Func 内部: void* Buffer = ...)
// 
// (4字节 编译器填充/对齐)
// 
// [Func 的栈帧边界与调用信息]
// main Stack Base(ebp) <-- (Func 的 EBP，值为 0x00A2FF04)
// Return Address       <-- (返回地址，值为 0x00BE13B9)
// 
// [Func 的参数 - 个体变量]
// Num1                 <-- (main 中压入的参数1，值为 10)
// Num2                 <-- (main 中压入的参数2，值为 20，即 pTest 指向的位置)
// 
// [Func 的参数 - 结构体 StructParam]
// Param.Param1         <-- (结构体成员1，值为 30)
// Param.Param2         <-- (结构体成员2，值为 20)
// Param.result         <-- (结构体成员3，传入时为0，Func内被改为50)
// 
// [main 的栈帧内容 - 局部变量]
// Num2                 <-- (main 的局部变量，值为 20)
// Num1                 <-- (main 的局部变量，值为 10)
// 
// [main 的栈帧内容 - 局部结构体 StructParam]
// Param.Param1         <-- (结构体成员1，值为 30)
// Param.Param2         <-- (结构体成员2，值为 20)
// Param.result         <-- (结构体成员3，值始终为 0)
// 
// TestResult           <-- (main 的局部变量，用于接收 Func 的返回值)
// 
// [main 的栈帧边界]
// mainCRTStartup Stack Base(ebp) <-- 0x00A2FF04 (main 的 EBP，保存了 CRT 启动代码的旧栈底基址)
// ----------------------------
// High Address (栈底方向)

// 有心的人可能会注意到，Func 内部的局部变量 pTest 和 Buffer 的地址和 main 中 局部变量、结构体 的地址位置关系。
// 在 x86 架构下，虽然栈通常从高地址向低地址生长，但局部变量在栈帧内的具体排列顺序取决于编译器的实现细节和栈帧布局策略（如内存对齐、调试信息等）。
// 因此，后声明的变量不一定总是位于更低的内存地址。