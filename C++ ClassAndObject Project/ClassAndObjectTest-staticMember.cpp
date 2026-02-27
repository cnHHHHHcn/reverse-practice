/**
 * @file ClassAndObjectTest-StaticMember.cpp
 * @brief C++ 静态成员变量底层原理验证实验
 *
 * @details
 * 本文件旨在通过内存地址分析，深入验证 C++ 静态成员变量 (static member variables)
 * 的存储机制、生命周期及与对象实例的独立性。
 *
 * 核心验证点：
 * 1. 【内存独立性】验证静态成员存储于全局数据区 (.data/.bss)，其地址完全独立于栈/堆上的对象实例。
 * 2. 【共享性验证】证明所有对象实例 (tg1, tg2) 访问静态成员时，指向的是同一物理内存地址。
 * 3. 【空间不占用】通过 sizeof 运算，证实静态成员不计入对象实例的内存大小。
 * 4. 【地址范围计算】手动计算并打印静态成员在全局区的连续内存分布范围。
 * 5. 【类外定义机制】演示静态成员必须在类外进行定义和初始化的链接规则。
 *
 * 预期现象：
 * - &tg1.s_a == &tg2.s_a == &Target::s_a
 * - sizeof(Target) 不包含 static 成员的大小
 * - 修改任意对象的 static 成员，所有对象及类名访问的值同步改变
 *
 * @warning
 * 本实验涉及底层内存地址打印与分析，输出结果依赖于具体编译器实现及内存对齐策略。
 * 静态成员在多线程环境下非线程安全 (Race Condition)，本测试仅在单线程下运行。
 *
 *	Let's Debug! 
 *    -> 操作路径: Visual Studio [调试] -> [窗口] -> [内存/即时/自动]
 *    -> 目标：亲眼见证静态成员在全局区的独立地址！
 * 
 * @author cnHHHHHcn
 * @date 2026-02-27
 * @version 1.0
 */

#include <iostream>

class Target {
/**
 * @brief 核心区别总结：静态 vs 普通 成员函数
 *
 * 1. 根本差异：静态函数无 `this` 指针，故不依赖对象实例。
 * 2. 访问权限：静态函数仅能访问静态成员（无法访问非静态成员）。
 * 3. 调用方式：静态函数可通过类名直接调用，无需构造对象。
 * 4. 多态限制：静态函数不能是虚函数 (virtual)，不支持重写与动态绑定。
 *
 * 总结：静态函数属于“类”，普通函数属于“对象”。
 */
public:
	int a = 0xAAAAAAAA;
	static char s_a;
	static short s_b;
	static int s_c;
	// static char test = 'T';	// Error: 带有类内初始值设定项的成员必须为常量
private:
	short b = 0xBBBB;
protected:
	char c = 0x43;
};



// ==========================================
// 【关键步骤】类外定义与初始化
// 格式：类型 类名::成员名 = 初始值;
// 这一步才真正分配了内存，解决了 "无法解析的外部符号" 错误
// 定义并初始化 public 静态成员
// ==========================================
char Target::s_a = 0x41;     
short Target::s_b = 0x4242;
int Target::s_c = 0x43434343; 

int main() {
	Target tg1, tg2;

	std::cout << "[ Reverse Engineering Progject : Static Variable Research ]\n" << std::endl;

	std::cout << std::hex;
	// void* pTargetStaticVariable = &tg1.s_a;
	// void* ptg = &tg1;
	// void* ptg = &tg2;
	std::cout << "Class Target Public Static s_a Address: " << (void*)&Target::s_a << std::endl;
	std::cout << "Instance Object tg1 Public Static s_a Address: " << (void*)& tg1.s_a << std::endl;
	std::cout << "Instance Object tg2 Public Static s_a Address: " << (void*)&tg2.s_a << std::endl;
	std::cout << std::endl;
	std::cout << "Class Target Public Static s_a: " << Target::s_a << std::endl;
	std::cout << "Instance Object tg1 Public Static s_a: " << (char)tg1.s_a << std::endl;
	std::cout << "Instance Object tg2 Public Static s_a: " << (char)tg2.s_a << std::endl;
	tg1.s_a = 0x30;
	std::cout << std::endl;
	std::cout << "Change Instance Object tg1 Public s_a" << std::endl;
	std::cout << "Class Target Public Static s_a: " << Target::s_a << std::endl;
	std::cout << "Instance Object tg1 Public Static s_a: " << (char)tg1.s_a << std::endl;
	std::cout << "Instance Object tg2 Public Static s_a: " << (char)tg2.s_a << std::endl;

	std::cout << std::endl;
	size_t ClassVariableSize = sizeof(Target);
	std::cout << "Class Target Variable Size: " << (size_t)ClassVariableSize << " Bytes" << std::endl;
	std::cout << "Instance Object tg1 Variable Memory Range: " << (void*)&tg1 << " - " << (void*)((char*)&tg1 + ClassVariableSize) << std::endl;
	std::cout << "Instance Object tg2 Variable Memory Range: " << (void*)&tg2 << " - " << (void*)((char*)&tg2 + ClassVariableSize) << std::endl;
	std::cout << std::endl;
	std::cout << "Class Target Public Static s_a Address: " << (void*)&Target::s_a << " (Size: 1 Bytes; Type: char)" << std::endl;
	std::cout << "Class Target Public Static s_b Address: " << (void*)&Target::s_b << " (Size: 2 Bytes; Type: short)" << std::endl;
	std::cout << "Class Target Public Static s_c Address: " << (void*)&Target::s_c << " (Size: 4 Bytes; Type: int)" << std::endl;
	size_t ClassStaticVariableSize = ((char*)&Target::s_c - (char*)&Target::s_a) + sizeof(int);
	std::cout << "Class Target Static Variable Size: " << std::dec << ClassStaticVariableSize << " Bytes" << std::hex << std::endl;
	std::cout << "Class Target Static Variable Memory Range: " << (void*)&Target::s_a << " - " << (void*)((char*)&Target::s_a + ClassStaticVariableSize) << std::endl;

	return 0;
}