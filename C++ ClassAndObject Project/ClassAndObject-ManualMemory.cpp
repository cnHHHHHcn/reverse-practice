/**
 * @file ClassAndObject-ManualMemory.cpp
 * @brief C++ 类对象内存布局解析与手动生命周期管理实验
 *
 * @details
 * 本文件演示了在不依赖编译器自动生成的构造/析构函数的情况下，
 * 如何通过 C 风格的手动内存操作来模拟 C++ 类的完整生命周期。
 * 核心机制包括：
 * 1. 【原始内存分配】使用 calloc 在堆上分配未初始化的原始内存块。
 * 2. 【手动构造模拟】通过全局函数 TargetInitiate 强行写入内存，模拟构造函数行为。
 * 3. 【内存布局穿透】利用指针偏移 (Pointer Arithmetic) 直接访问 private/protected 成员。
 * 4. 【手动析构模拟】通过全局函数 TargetDestory 清理数据并 free 内存。
 *
 * 【重要说明 / CRITICAL NOTE】
 * 1. **非 RAII 实现**：
 *    - 真正的 RAII (Resource Acquisition Is Initialization) 应利用栈对象析构自动释放资源。
 *    - 本代码依赖程序员显式调用 ClassDeleteOpera，若忘记调用将导致内存泄漏。
 *    - 此模式常见于逆向工程分析（还原编译器底层行为）或嵌入式受限环境，而非现代 C++ 最佳实践。
 * 2. **硬编码偏移量风险**：
 *    - 代码中 *(short*)((char*)pObject + 0x4) 强依赖特定编译器 (MSVC) 的内存对齐策略。
 *    - 若成员变量类型或顺序改变，偏移量 0x4/0x6 将失效，导致数据错乱。
 * 3. **学习价值**：
 *    - 帮助理解 this 指针的本质（即对象首地址）。
 *    - 揭示 C++ 成员变量在内存中的真实排列顺序（Public/Private/Protected 无区别，仅访问权限不同）。
 *
 * @warning
 * 本代码涉及底层内存读写，包含硬编码偏移量和手动内存管理。
 * 仅用于逆向原理研究与教学，严禁在生产环境使用此类手动管理方式。
 *
 *  Let's Debug!
 *    -> 操作路径: Visual Studio [调试] -> [窗口] -> [内存 1] (Memory 1)
 *    -> 目标：
 *       1. 【见证内存布局】：在 TargetInitiate 执行后，观察内存窗口。
 *          确认 0x00 处是 int a (4字节), 0x04 处是 short b, 0x06 处是 char c。
 *          验证访问控制符 (public/private) 不影响内存物理位置。
 *       2. 【追踪指针变换】：单步执行 ClassNewOpera。
 *          观察 calloc 返回的 void* 如何被强制转换为 Target* 并传入初始化函数。
 *       3. 【监控生命周期】：在 main 函数末尾，确认 ClassDeleteOpera 是否将内存清零并释放。
 *          对比若不调用该函数，内存窗口中的数据是否残留 (内存泄漏)。
 *
 * @author [你的名字]
 * @date 2026-02-27
 * @version 1.0 (Experimental - Manual Memory Management)
 */

#include <iostream>
#include <stdlib.h>

 // ================= 目标类定义 (内存布局模板) =================
 /**
  * @brief 用于测试内存布局的靶子类
  * @note 此类故意不写构造函数/析构函数，以便演示手动初始化过程
  */
class Target {
public:
    int a;          // 偏移量 0x00 (4字节)

    // 普通成员函数：第一个参数隐含 this 指针
    void OutThisPointer() {
        std::cout << "Current instance Address (this): " << this << std::endl;
    };

    void OutMemberInfo() {
        std::cout << "Public int a (Offset 0x0): " << a << std::endl;
        // 以下两行虽然能访问私有/保护成员，但演示了通过 this 指针的直接访问
        std::cout << "Private short b (Offset 0x4): " << b << std::endl;
        std::cout << "Protected char c (Offset 0x6): " << c << std::endl;
    };

private:
    short b;        // 偏移量 0x04 (2字节) - 注意：受对齐影响，可能占用2字节

protected:
    char c;         // 偏移量 0x06 (1字节) - 注意：后续可能有填充字节(padding)
};

// ================= 手动构造与析构模拟 =================

/**
 * @brief 模拟构造函数：手动初始化内存布局
 * @param pObject 指向已分配但未初始化内存的指针
 * @warning 硬编码偏移量 (0x4, 0x6) 依赖 MSVC x64 默认对齐策略
 */
void TargetInitiate(Target* pObject) {
    if (!pObject) return;

    // 1. 初始化 public 成员 (直接访问)
    pObject->a = 0x11111111;

    // 2. 初始化 private 成员 (通过指针偏移暴力写入)
    // 逻辑：(char*)pObject 转为字节指针 -> +4 跳过 int a -> 强转为 short* -> 赋值
    *(short*)((char*)pObject + 0x4) = 0x2222;

    // 3. 初始化 protected 成员 (通过指针偏移暴力写入)
    // 逻辑：+6 跳过 int a(4) + short b(2) -> 强转为 char* (实际代码里强转的是short*取低8位，这里修正为char*)
    // 原代码逻辑：*(short*)((char*)pObject + 0x6) = 0x33; 
    // 修正说明：原代码用 short* 接收 0x33 没问题，但语义上 c 是 char。
    // 保持原逻辑以匹配你的测试值，但需注意这里实际上写入了2字节 (0x33 0x00)
    *(unsigned char*)((char*)pObject + 0x6) = 0x33;
};

/**
 * @brief 模拟析构函数：手动清理内存数据
 * @param pObject 指向待释放对象的指针
 */
void TargetDestory(Target* pObject) {
    if (!pObject) return;

    // 清零数据，防止释放后残留敏感信息 (虽然 free 后不应再访问)
    pObject->a = 0;
    *(short*)((char*)pObject + 0x4) = 0;
    *(unsigned char*)((char*)pObject + 0x6) = 0;
};

// ================= 内存管理接口 (C-Style API) =================

/**
 * @brief 封装内存分配与初始化 (类似 new 操作符的重载)
 * @return 指向已初始化对象的指针
 */
Target* ClassNewOpera() {
    // 1. 分配原始内存 (内容为0)
    void* AllocAddress = calloc(1, sizeof(Target));
    if (!AllocAddress) return nullptr;

    // 2. 手动调用“构造函数”
    TargetInitiate((Target*)AllocAddress);

    return (Target*)AllocAddress;
}

/**
 * @brief 封装清理与释放 (类似 delete 操作符的重载)
 * @param pObject 待释放的对象指针
 */
void ClassDeleteOpera(Target* pObject) {
    if (!pObject) return;

    // 1. 手动调用“析构函数”清理数据
    TargetDestory(pObject);

    // 2. 释放堆内存
    free((void*)pObject);
}

// ================= 主测试入口 =================
int main(){

	std::cout << "[ Reverse Engineering Project : ManualMemory ]" << std::endl;

    // 1. 手动创建对象 (模拟 new Target())
	Target* tg = ClassNewOpera();    // 后续输出使用十六进制，方便观察内存地址
	std::cout << std::hex;

    // 2. 验证对象信息
	std::cout << "Class Target Initiated Instance Object tg" << std::endl; 
	std::cout << std::endl;
	std::cout << "Instance Object tg Addess: " << tg << std::endl;

    // 验证 this 指针是否等于对象地址
	tg->OutThisPointer();
	std::cout << std::endl; 
	std::cout << "Instance Object tg Variable Overall" << std::endl;
    
    // 验证能否正确读取通过偏移量写入的数据
	tg->OutMemberInfo();
	std::cout << std::endl; 

    // 3. 手动销毁对象 (模拟 delete tg)
// 【关键】：如果不执行这一行，将发生内存泄漏 (Memory Leak)
	ClassDeleteOpera(tg);
	std::cout <<  "Released Instance Object tg" << std::endl;
	return 0;
} 
