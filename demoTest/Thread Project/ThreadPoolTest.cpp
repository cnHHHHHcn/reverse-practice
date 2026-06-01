#include <windows.h>
#include <iostream>

const int Min = 1;
const int Max = 10;

int Count = 0;

/*
 * 【线程池工作项的回调函数】
 * 函数签名是 Windows API 强制规定的，必须严格遵守：
 * 返回值必须是 VOID，调用约定必须是 NTAPI 或 CALLBACK(核心调用就是 _stdcall)。
 * 
 * 函数签名 void NTAPI/CALLBACK/WINAPI/_stdcall ***Proc(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work);
 * 
 * 参数解释：
 * 1. PTP_CALLBACK_INSTANCE Instance
 *    - 作用：当前这次回调的“执行实例”句柄。
 *    - 场景：由系统自动生成。如果你想在中途取消本次回调，或者查询本次回调的环境信息时使用。
 *
 * 2. PVOID Context
 *    - 作用：自定义的“上下文参数”。
 *    - 场景：对应 CreateThreadpoolWork 的第二个参数。相当于给线程递工具包，
 *            比如传入一个文件路径字符串，让不同的线程处理不同的文件。
 *            参数过多的话建议写成结构体。
 *
 * 3. PTP_WORK Work
 *    - 作用：当前正在执行的“工作对象”本身。
 *    - 场景：对应 CreateThreadpoolWork 的返回值。在函数内部可以拿到这张“工单”的指针，
 *            常用于在任务执行完毕后，自己调用 CloseThreadpoolWork 来释放自己。
 */
void NTAPI AddCore(PTP_CALLBACK_INSTANCE Instance, PVOID Context, PTP_WORK Work) {
    for (int i = 0; i < 100000; i++) {
         InterlockedAdd((LONG*)&Count, 1);
    }
}

int main() {
    // ================== 专属线程池的创建与关联 ==================

    // 1. 创建专属线程池
    PTP_POOL hThreadPool = CreateThreadpool(NULL);
    if (hThreadPool == NULL) {
        std::cout << "创建线程池失败" << std::endl;
        return 0;
    }
    // 2. 设置线程池的线程数量
    SetThreadpoolThreadMinimum(hThreadPool, Min);
    SetThreadpoolThreadMaximum(hThreadPool, Max);

    // 3. 初始化“回调环境”（相当于制定一套任务派发规则）
    TP_CALLBACK_ENVIRON callbackEnv;
    InitializeThreadpoolEnvironment(&callbackEnv);

    // 4. 将专属线程池与回调环境关联起来（把任务规则和我们的办公楼绑定）
    SetThreadpoolCallbackPool(&callbackEnv, hThreadPool);

    // ================== 任务的创建与提交 ==================

    // 1. 创建 Max(10) 个“工作任务对象”
    PTP_WORK workItems[Max];
    for (int i = 0; i < Max; i++) {
        // 第三个参数传 NULL 表示使用系统默认的线程池环境
        workItems[i] = CreateThreadpoolWork(AddCore, NULL, &callbackEnv);
    }

    // 2. 把这 Max(10) 个任务全部扔进线程池，让线程们开始干活
    for (int i = 0; i < Max; i++) {
        if(workItems[i])
            SubmitThreadpoolWork(workItems[i]);
    }

    // ================== 等待与清理 ==================
    
    // 3. 依次等待每个工作任务对象执行完毕
    for (int i = 0; i < Max; i++) {
        if (workItems[i])
            // 第二个参数传 FALSE：表示“不取消任务，老老实实等它跑完”
            WaitForThreadpoolWorkCallbacks(workItems[i], FALSE);
    }

    // 4. 打扫战场：关闭工作任务对象（释放内存）
    for (int i = 0; i < Max; i++) {
        if (workItems[i])
            CloseThreadpoolWork(workItems[i]);
    }

    // ================== 专属线程池的销毁 ==================

    // 5. 销毁回调环境（销毁任务派发规则）
    DestroyThreadpoolEnvironment(&callbackEnv);

    // 6. 关闭专属线程池（拆除办公楼，释放系统资源）
    CloseThreadpool(hThreadPool);

    std::cout << Count << std::endl;
    return 0;
}