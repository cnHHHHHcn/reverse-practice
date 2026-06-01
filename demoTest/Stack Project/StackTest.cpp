// 编译 Release x86
// 项目配置属性 -> C/C++ -> 优化(已禁用(/Od))

#include <iostream>

/* Tips - 编译器优化
 * 如果函数内没有用到形参，则传入寄存器
 */

struct StructParam {
	int Param1;
	int Param2;
	int result;
};


// try: 试试给第三个参数类型 StructParam 改为 StructParam&，看看栈布局和参数传递方式有什么变化。
//		理解引用参数在栈上的表现，以及它与值传递的区别。
int Func(int Num1, int Num2, StructParam Param) {
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