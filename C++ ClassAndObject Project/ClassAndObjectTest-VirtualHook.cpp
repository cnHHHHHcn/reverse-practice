/**
 * @file ClassAndObjectTest-VirtualHook.cpp
 * @brief C++ 虚函数表劫持 (VTable Hooking) 与内存布局穿透实验
 *
 * @details
 * 本文件演示了如何通过直接操作对象内存布局，实现运行时多态的“劫持”。
 * 核心机制包括：
 * 1. 【虚表解析】遍历对象头部的 vptr，提取虚函数地址列表。
 * 2. 【内存伪造】在堆 (Heap) 上动态分配可写内存，复制原始虚表内容。
 * 3. 【指针重定向】修改对象 vptr，使其指向伪造的虚表，从而拦截函数调用。
 * 4. 【偏移量访问】通过硬编码偏移量 (0x8) 直接读写 protected 成员变量 (m_Value)。
 *
 * 【高危警告 / CRITICAL WARNING】
 * 1. **非生产代码**：本代码仅用于底层原理研究、逆向工程学习或调试测试。
 *    严禁在任何生产环境、商业项目或稳定系统中使用此类技术。
 * 2. **未定义行为 (UB)**：
 *    - 硬编码偏移量 (0x8) 依赖于特定的编译器版本、架构 (x64) 及对齐策略。
 *    - 更换环境极易导致内存越界访问 (Access Violation)。
 * 3. **内存管理风险**：
 *    - 手动 calloc/free 虚表内存极易引发内存泄漏或双重释放 (Double Free)。
 *    - 若对象析构时未恢复原始 vptr，将导致程序崩溃。
 * 4. **安全性**：此类技术常被恶意软件利用，编译后可能被杀毒软件误报为病毒。
 *
 * @warning 
 * 本代码涉及底层内存操作，包含硬编码偏移量和手动内存管理。
 * 仅用于技术研究与教学，严禁在生产环境使用。
 * 
 *  Let's Debug!
 *    -> 操作路径: Visual Studio [调试] -> [窗口] -> [内存 1] (Memory 1) & [即时] (Immediate)
 *    -> 目标：
 *       1. 【见证偷梁换柱】：在 CheatClassVirtualFunc 执行前后，对比对象头部 (vptr) 的值。
 *          观察它如何从 .rdata (只读代码段) 跳变到 Heap (堆内存)，证明虚表已被伪造。
 *       2. 【验证函数拦截】：在 Dtg->Add() 处下断点，单步执行 (F10/F11)。
 *          确认指令跳转地址不再是 DerivedTarget::Add，而是我们的 Multiply 函数。
 *       3. 【透视内存穿透】：在 Multiply/Divide 函数内，查看 (char*)Dtg + 0x8 处的内存值。
 *          亲眼见证 double 类型的 m_Value 如何被直接暴力改写，绕过所有封装保护。
 *       4. 【监控生命周期】：观察 ReleaseHeap 逻辑执行时，旧堆内存是否被正确释放，
 *          警惕 Access Violation (0xC0000005) 在错误释放只读内存时爆发。
 * - 代码中的 `ReleaseHeap` 参数仅为演示逻辑，实际应用中需更严谨的生命周期管理。
 *
 * @author [你的名字]
 * @date 2026-02-27
 * @version 1.0 (Experimental)
 */

#include <iostream>
#include <vector>
#include <windows.h>

 // ================= 基类定义 =================
class BaseTarget {
public:
    // 虚函数：会在虚表中占据位置 (索引 0)
    virtual void Add(double Param) {};
    // 虚函数：会在虚表中占据位置 (索引 1)
    virtual void Sub(double Param) {};

    // 普通成员函数：不在虚表中，直接调用
    double GetValue() {
        return m_Value;
    };

protected:
    // 受保护成员：派生类可访问，位于对象内存中
    double m_Value = 0;
};

// ================= 派生类定义 =================
class DerivedTarget : public BaseTarget {
public:
    // 重写基类虚函数
    void Add(double Param) override {
        m_Value += Param;
    };
    void Sub(double Param) override {
        m_Value -= Param;
    };
};

// 类型别名：虚函数表列表 (存储函数地址)
typedef std::vector<void*> VTFList;

// ================= 黑客函数：直接内存修改 =================
/**
 * @brief 模拟乘法操作 (通过指针偏移直接修改内存)
 * @warning 硬编码偏移量 0x8 依赖特定编译器/架构 (64位下 vptr=8字节, 无padding)
 */
void Multiply(DerivedTarget* Dtg, double Param) {
    // 1. 计算 m_Value 的地址：对象首地址 + 8字节 (跳过 vptr)
    // 注意：这是不安全的硬编码，推荐使用 offsetof
    void* ptg_m_Value = ((char*)Dtg + 0x8);

    // 2. 强制类型转换为 double 指针
    double* tg_m_Value = (double*)ptg_m_Value;

    // 3. 直接修改内存中的值
    *tg_m_Value *= Param;
}

/**
 * @brief 模拟除法操作 (通过指针偏移直接修改内存)
 */
void Divide(DerivedTarget* Dtg, double Param) {
    void* ptg_m_Value = ((char*)Dtg + 0x8);
    double* tg_m_Value = (double*)ptg_m_Value;
    *tg_m_Value /= Param;
}

// ================= 虚表解析工具 =================
/**
 * @brief 遍历虚函数表，提取所有函数地址
 * @warning MSVC 的虚表通常不以 nullptr 结尾，此处的 while(FnAddress) 可能导致越界读取
 *          仅在虚表末尾恰好为 0 或遇到非法地址崩溃前能工作 (极度危险)
 */
VTFList GetClassVirtualTable(void* pVirtualTableAddr) {
    void* FnAddress = nullptr;
    VTFList VirtualTableFuncList;
    int maxCount = 20; // 假设虚函数不会超过 20 个，防止死循环
    do {
        // 取出当前索引的函数地址
        FnAddress = *(void**)pVirtualTableAddr;

        // 如果地址有效则加入列表 (若为 0 则停止)
        VirtualTableFuncList.push_back(FnAddress);

        // 指针后移一个单位 (sizeof(void*))，指向下一个函数指针
        pVirtualTableAddr = (void*)((unsigned long long)pVirtualTableAddr + sizeof(char*));
        if (VirtualTableFuncList.size() > maxCount) break; // 安全阀
    } while (FnAddress); // 危险：依赖空指针作为结束标志

    return VirtualTableFuncList;
}
/**
 * @brief 打印对象内存布局及虚表详情
 */
void DisplayClassVirtualFunc(void* pObject) {
    // 获取对象头部的 vptr (指向虚表的指针)
    void* pVirtualTableAddr = *(void**)pObject;
    void* FnAddress = nullptr;

    // 解析虚表内容
    VTFList VirtualTableFuncList = GetClassVirtualTable(pVirtualTableAddr);

    std::cout << std::hex;
    std::cout << "Instance Object Address: " << pObject << std::endl;
    std::cout << "Instance Object Virtual Table Address: " << pVirtualTableAddr << std::endl;
    std::cout << "Instance Object Virtual Table Context Overall: " << std::endl;

    // 打印每个虚函数的地址
    for (int i = 0; i < VirtualTableFuncList.size(); i++)
        std::cout << "Virtual Table Pos:" << std::dec << i + 1 << "   Address: " << std::hex << VirtualTableFuncList[i] << std::endl;

    std::cout << "Instance Object Pointer Map: " << std::endl;
    std::cout << pObject << " -> " << pVirtualTableAddr << " -> {";

    // 打印映射关系
    for (int i = 0; i < VirtualTableFuncList.size(); i++) {
        std::cout << VirtualTableFuncList[i];
        if (i != VirtualTableFuncList.size() - 1) std::cout << ", ";
    }
    std::cout << "}" << std::endl;
}

// ================= 劫持配置结构体 =================
struct VirtualFnData {
    int Index;      // 要劫持的虚函数索引 (0=Add, 1=Sub)
    void* FuncAddr; // 新的函数地址 (Hook 函数)
};

/**
 * @brief 核心劫持函数：伪造虚表并替换 vptr
 * @param pObject 目标对象指针
 * @param VirtualFn 劫持配置 (索引 + 新函数)
 * @param ReleaseHeap 是否释放旧的堆内存 (逻辑有缺陷，仅演示用)
 *
 * @process
 * 1. 读取当前虚表内容到 vector
 * 2. 修改 vector 中指定索引的函数地址
 * 3. 在堆上 calloc 一块新内存，复制修改后的虚表
 * 4. 将对象的 vptr 指向这块新内存 (完成劫持)
 */
bool CheatClassVirtualFunc(void* pObject, VirtualFnData VirtualFn, bool ReleaseHeap) {
    if (!pObject) return false;

    // 1. 获取当前虚表内容 (注意：这里每次都会重新解析，可能读到非法内存)
    VTFList VirtualTableFuncList = GetClassVirtualTable(*(void**)pObject);
    int VirtualFnCount = VirtualTableFuncList.size();

    // 检查索引是否越界
    if (VirtualFnCount < VirtualFn.Index) return false;

    // 2. 在内存列表中替换函数地址
    VirtualTableFuncList[VirtualFn.Index] = VirtualFn.FuncAddr;

    // 3. 【关键】在堆上分配可写内存作为"伪造的虚表"
    // 注意：这里硬编码了 3 个指针大小，应使用 VirtualFnCount
    void* pVirtualFunctionAddr = calloc(3, sizeof(void*));
    if (!pVirtualFunctionAddr) return false;

    // 复制修改后的虚表内容到堆内存
    memcpy(pVirtualFunctionAddr, VirtualTableFuncList.data(), sizeof(void*) * VirtualFnCount);

    // 4. 【可选】尝试释放旧内存 (逻辑错误：*(void**)pObject 指向的是 .rdata 只读段或上一次的堆，不能直接 free)
    if (ReleaseHeap)
        free(*(void**)pObject); // 危险：如果指向 .rdata 会崩溃，如果指向旧堆且未保存也会出错

    // 5. 【偷梁换柱】修改对象头部的 vptr，指向我们伪造的堆内存
    *(void**)pObject = pVirtualFunctionAddr;

    return true;
}

int main() {
    // 创建对象 (在堆上，方便控制生命周期)
    DerivedTarget* Dtg = new DerivedTarget();
    VTFList New, Old;

    std::cout << "[ Reverse Engineering Progject : Virtual Table Hooking ]\n" << std::endl;
    std::cout << "=== [Before Hook] ===" << std::endl;

    // 保存原始虚表信息 (用于对比)
    Old = GetClassVirtualTable(*(void**)Dtg);
    DisplayClassVirtualFunc(Dtg);

    // 测试正常逻辑
    Dtg->Add(10.0);
    std::cout << "After Add(10): " << std::dec << Dtg->GetValue() << std::hex << std::endl; // 应为 10

    Dtg->Sub(5.0);
    std::cout << "After Sub(5): " << std::dec << Dtg->GetValue() << std::hex << std::endl;  // 应为 5

    // ================= 开始劫持 =================
    VirtualFnData VFD;

    // 第一次劫持：将索引 0 (Add) 替换为 Multiply
    VFD.Index = 0;
    VFD.FuncAddr = &Multiply;
    // ReleaseHeap=false: 不尝试释放旧表 (因为旧表在 .rdata，不能 free)
    CheatClassVirtualFunc(Dtg, VFD, false);

    // 第二次劫持：将索引 1 (Sub) 替换为 Divide
    // 注意：由于 CheatClassVirtualFunc 内部逻辑缺陷，这次操作可能会重置索引 0 的修改!
    VFD.Index = 1;
    VFD.FuncAddr = &Divide;
    // ReleaseHeap=true: 尝试释放 (这里会尝试 free 上一次 calloc 的内存，逻辑勉强成立但非常脆弱)
    CheatClassVirtualFunc(Dtg, VFD, true);

    std::cout << "\n=== [After Hook] ===" << std::endl;
    New = GetClassVirtualTable(*(void**)Dtg);
    DisplayClassVirtualFunc(Dtg);

    // 测试劫持后的逻辑
    // 预期：Add 被劫持为 Multiply (乘 10)，Sub 被劫持为 Divide (除 5)
    // 当前值是 5.0
    Dtg->Add(10.0);
    std::cout << "After Hooked Add(10) [Should be *10]: " << std::dec << Dtg->GetValue() << std::hex << std::endl;

    Dtg->Sub(5.0);
    std::cout << "After Hooked Sub(5) [Should be /5]: " << std::dec << Dtg->GetValue() << std::hex << std::endl;
    
    std::cout << std::endl;

    // 打印 加、减、乘、除 函数表
    std::cout << "=== [Function Address] ===" << std::endl;
    std::cout << std::hex;
    std::cout << "Add: " << Old[0] /* Add */ << std::endl;
    std::cout << "Sub: " << Old[1] /* Sub */ << std::endl;
    std::cout << "Multiply: " << New[0] /* Multiply */ << std::endl;
    std::cout << "Divide: " << New[1] /*Divide*/ << std::endl;
 

    // 清理内存 (防止泄漏)
    // 实际项目中需要恢复 vptr 并 delete[] 伪造的表
    delete Dtg;

    return 0;
}