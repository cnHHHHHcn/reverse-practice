/**
 * @file ClassAndObjectTest-Access.cpp
 * @brief 演示 C++ 内存布局穿透 (Memory Layout Penetration) 与访问控制 bypass
 *
 * @details
 * 本文件通过指针算术 (Pointer Arithmetic) 和类型强制转换 (Type Casting)，
 * 直接操作对象在内存中的物理地址，从而绕过编译期的访问控制检查 (private/protected)。
 *
 * 核心原理：
 * 1. C++ 的对象内存布局是连续且确定的 (Standard Layout)。
 * 2. 访问修饰符 (public/private/protected) 仅为编译期语法约束，不占用运行时内存。
 * 3. 只要计算出成员变量相对于对象首地址的偏移量 (Offset)，即可通过裸指针直接读写。
 *
 * 技术关键词：
 * - Memory Layout Penetration (内存布局穿透)
 * - Offset-based Access (基于偏移量的访问)
 * - Type Punning (类型双关)
 * - Encapsulation Bypass (封装绕过)
 *
 * @warning
 * 此操作破坏了封装性，依赖于特定的编译器内存对齐策略。
 * 若类定义变更或编译器优化策略改变，偏移量计算将失效，导致未定义行为 (UB)。
 * 仅用于底层原理研究、调试或逆向工程，严禁在生产环境业务逻辑中使用。
 *
 *	Let's Debug!
 *    -> 操作路径: Visual Studio [调试] -> [窗口] -> [内存/即时/自动]
 *    -> 目标：亲眼见证指针偏移如何绕过 private，protected 限制修改内存！
 *
 * @author cnHHHHHcn
 * @date 2026-02-27
 */
#include <iostream>

class Target {
// this 是常量指针，不能更改as
public:
    int a = 0xAAAAAAAA;
    void Func() {
        Init();
        std::cout << "Debug Func" << std::endl;
        std::cout << "Public a:" << a << std::endl;
        std::cout << "Private b:" << b  << std::endl;
        std::cout << "Protected c:" << c << std::endl;
    }
private:
    short b = 0xBBBB;
    void Init() {
        std::cout << "Class Taget Object Address:" << this << std::endl;
    }
protected:
    char c = 0x43;
};


int main()
{
    Target tg1, tg2;
    char* ptg = nullptr;
    
    std::cout << "[ Reverse Engineering Project : Memory Layout Penetration ]\n" << std::endl;
    
    std::cout << std::hex;

    ptg = (char*)&tg1;
    std::cout << "tg1 Address:" << (void*)ptg << std::endl; 
    std::cout << "=== [Object tg1 before Penetration] ===" << std::endl;
    tg1.Func();
    tg1.a = 0x11111111;
    *(short*)(ptg + sizeof(int)) = 0xB00B;
    *(char*)(ptg + sizeof(int) + sizeof(short)) = 0x41;
    std::cout << "=== [Object tg1 After Penetration] ===" << std::endl;
    tg1.Func();

    std::cout << std::endl;

    ptg = (char*)&tg2;
    std::cout << "tg2 Address:" << (void*)ptg << std::endl;
    std::cout << "=== [Object tg2 before Penetration] ===" << std::endl;
    tg2.Func();
    tg2.a = 0x22222222;
    *(short*)(ptg + sizeof(int)) = 0xBB00;
    *(char*)(ptg + sizeof(int) + sizeof(short)) = 0x42;
    std::cout << "=== [Object tg2 After Penetration] ===" << std::endl;
    tg2.Func();
    return 0;
}
