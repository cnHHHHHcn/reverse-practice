# reverse-practice

> 逆向工程实战手册：从 C++ 底层到 Windows 核心

这是我个人从零开始学习逆向工程的完整实战记录。仓库不仅包含系统化的学习文档和知识笔记，还配套了从 C++ 内存布局、汇编控制流、栈帧分析到 PE/PDB 解析的实践代码，希望通过“理论 + 实验 + 调试”的方式，把高级语言背后的内存与机器执行过程真正看清楚。

## 仓库内容

```text
reverse-practice/
├─ Reverse-book/                 系统化的逆向学习文档
├─ Note/                         x86、内存、符号等专题笔记
├─ demoTest/                     实践代码与实验程序
│  ├─ Asm Project/               C/C++ 与汇编对照实验
│  ├─ C++ ClassAndObject Project/
│  ├─ Memory Project/
│  ├─ ParserWndowsFormat Project/
│  ├─ Stack Project/
│  ├─ Thread Project/
│  └─ float_test.c
├─ R3 Debug Project/             调试工程预留目录
└─ LICENSE
```

## 学习路线

建议按照“底层理论 -> 汇编基础 -> 内存与对象模型 -> Windows 核心机制”的顺序阅读。

### 1. 理论奠基

- [Reverse-Basic.pdf](./Reverse-book/Reverse-Basic.pdf)：逆向工程入门，覆盖 C++ 内存本质、汇编指令和栈帧机制。
- [Reverse-System.pdf](./Reverse-book/Reverse-System.pdf)：Windows 系统与 PE 相关基础。
- [Reverse-Project.pdf](./Reverse-book/Reverse-Project.pdf)：综合项目实践说明。
- [Note](./Note/)：配套知识笔记。

核心笔记包括：

- `AsmNote.txt`：x86 汇编指令、栈操作和函数调用约定。
- `Symbol.txt`：C++ 名称修饰与符号还原。
- `x86 Segment Register Note.txt`：段寄存器与保护模式。
- `Memory Note.txt`：虚拟内存、分页和地址转换。

### 2. 汇编对照与编译器行为

[demoTest/Asm Project](./demoTest/Asm%20Project/) 是源码与反汇编的直接对照实验集。每个主题都提供 x86/x64 Release 程序、PDB 符号和 IDA 数据库，适合观察高级语言如何转换为机器指令。

| 模块 | 主要内容 | 观察重点 |
|---|---|---|
| [Branch](./demoTest/Asm%20Project/Branch/) | `if`、多分支、`switch`、编译优化 | 条件跳转、跳转表、常量传播、死代码消除 |
| [Loops](./demoTest/Asm%20Project/Loops/) | `for`、嵌套循环、`do-while`、`break/continue` | 循环条件、循环回边、循环变量 |
| [Pointer](./demoTest/Asm%20Project/Pointer/) | 结构体数组、指针参数、指针遍历、排序 | 字段偏移、数组寻址、指针算术 |
| [Call_And_Recursion](./demoTest/Asm%20Project/Call_And_Recursion/) | 普通递归、尾递归、函数调用 | 栈帧、参数传递、返回值和尾调用 |
| [C_try](./demoTest/Asm%20Project/C_try/) | `setjmp/longjmp` 模拟异常 | 执行环境保存、恢复和非正常跳转 |
| [C++_try](./demoTest/Asm%20Project/C++_try/) | C++ `try/catch` 与自定义异常 | 异常对象、异常表、栈展开 |
| [ClassAndObject_And_STL](./demoTest/Asm%20Project/ClassAndObject_And_STL/) | 继承、虚函数、RTTI、STL | vptr/vtable、间接调用、堆分配 |

完整使用说明、x86/x64 调用约定对照和阅读顺序见 [Asm Project 说明](./demoTest/Asm%20Project/readme.md)。

### 3. 内存、对象与函数调用

#### 栈帧与流程控制

[Stack Project](./demoTest/Stack%20Project/) 用于理解 x86 函数调用和栈帧变化：

- `StackView.cpp`：观察 `EBP`、`ESP`、参数和局部变量在调用过程中的变化。
- `StackHijack.cpp`：通过修改栈中的返回地址改变控制流，理解函数返回和 Shellcode 跳转。

#### C++ 对象模型

[C++ ClassAndObject Project](./demoTest/C%2B%2B%20ClassAndObject%20Project/) 通过实践观察以下机制：

- 对象内存布局和成员访问。
- `private` 访问控制与实际内存可见性。
- 静态成员的存储位置。
- `new/delete` 的手动内存管理过程。
- 通过篡改 `vptr` 观察虚函数表和动态绑定。

#### 内存扫描与查看

[Memory Project](./demoTest/Memory%20Project/) 包含：

- `MemoryView.cpp`：内存查看。
- `MemoryScanner.cpp`：内存扫描。

### 4. Windows 文件格式与并发

#### PE/PDB 解析

[ParserWndowsFormat Project](./demoTest/ParserWndowsFormat%20Project/) 包含 PE 与 PDB 解析相关代码：

- `PEParser.cpp/.h`：PE 文件结构解析。
- `PDBParser.cpp/.h`：PDB 符号信息解析。
- `NetDownloader.cpp/.h`：网络下载辅助。

#### 多线程与线程池

[Thread Project](./demoTest/Thread%20Project/) 用于练习 Windows 并发编程：

- `ThreadTest.cpp`：使用 `CreateThread` 和同步原语创建线程。
- `ThreadPoolTest.cpp`：使用 Windows 线程池执行并发任务。

#### 浮点数格式

[float_test.c](./demoTest/float_test.c) 用于验证 IEEE 754 浮点数的内存表示。

## 使用方式

1. 先阅读 `Reverse-book/` 中的 PDF，建立内存、汇编和 PE 的基础概念。
2. 再阅读 `Note/` 中的专题笔记，补充指令、符号、段寄存器和虚拟内存知识。
3. 学习 `Asm Project` 时，先看源码，再运行 EXE，最后用 IDA 和 PDB 对照反汇编。
4. 使用 Visual Studio 打开 C++ 示例，配合“内存窗口”“调用堆栈”和“反汇编窗口”单步调试。
5. 使用 IDA 打开 `.i64` 数据库，或打开 `.exe` 并加载同目录下匹配的 `.pdb`。

建议环境：

- Windows 10/11。
- Visual Studio 2022 或可用的 MSVC 工具链。
- x86/x64 Developer Command Prompt。
- IDA Pro/IDA Free。
- C++17。

克隆仓库：

```bat
git clone https://github.com/cnHHHHHcn/reverse-practice.git
```

## 说明

- `Asm Project` 目录中的 EXE、PDB 和 `.i64` 是预先构建并分析好的文件。
- 汇编结果会受到编译器版本、优化选项、运行库和目标架构影响，应以实际反汇编为准。
- 部分源码中的中文字符串使用 GBK 编码，终端代码页不匹配时可能出现乱码。
- 本项目中的技术仅用于安全研究、教学和底层原理学习。

## 作者心路

> “逆向工程的本质不是破坏，而是极致的理解。”

这个项目记录了我从对内存一无所知，到能够编写汇编对照实验、解析 PE/PDB、观察虚函数表和栈帧变化的过程。希望这份包含 **Code（代码）**、**Note（笔记）** 和 **Book（文档）** 的记录，能为同样对底层技术感兴趣的人提供一份真实参考。

## 免责声明

本项目所有代码与文档仅供安全研究与教学使用，请勿用于非法用途。
