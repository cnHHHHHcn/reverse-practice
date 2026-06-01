#include <windows.h>
#include <iostream>

int Count = 0;
HANDLE hMutex = NULL;

 /*
  * 函数签名是 Windows API 强制规定的，必须严格遵守：
  * 返回值必须是 DWORD，调用约定必须是 NTAPI 或 CALLBACK(核心调用就是 _stdcall)。
  *
  * 函数签名 DWORD NTAPI/CALLBACK/WINAPI/_stdcall ThreadProc(LPVOID lpParameter);
  *
  * 参数解释：
  *
  *  LPVOID lpParameter
  *    - 作用：自定义的“上下文参数”，可省。
  *    - 场景：相当于给线程递工具包，
  *            比如传入一个文件路径字符串，让不同的线程处理不同的文件。
  *            参数过多的话建议写成结构体。
  */

DWORD NTAPI AddCore(LPVOID lpParameter) {
    // 1. 请求互斥体的所有权（相当于加锁）。
    // INFINITE 表示如果拿不到锁，就一直死等，直到其他线程释放。
    WaitForSingleObject(hMutex, INFINITE);

    // 2. 进入临界区，开始安全地操作共享资源
    for (int i = 0; i < 100000; i++) {
        // 依然建议使用 InterlockedAdd 代替 Count++。
        // 即使外面有互斥体保护，原子操作也能防止极端情况下的数据竞争。
        InterlockedAdd((LONG*)&Count, 1);
    }

    // 3. 释放互斥体的所有权（相当于解锁），让其他等待的线程能抢到锁。
    ReleaseMutex(hMutex);
    return 0;
}

int main()
{
    // 创建互斥体
    // 第二个参数 FALSE：表示创建该互斥体的线程（主线程）初始不拥有它。
    // 第三个参数 L"A"：给互斥体起个名字（可选），如果传 NULL 则是无名互斥体。
    hMutex = CreateMutexW(NULL, FALSE, L"A");
    if (hMutex == NULL) return 0;

    HANDLE hThreads[5];
    ZeroMemory(hThreads, sizeof(HANDLE) * 5);
    // 创建 5 个传统线程
    for (int i = 0; i < 5; i++) {
        // CreateThread(安全属性, 栈大小, 线程函数指针, 传给线程的参数, 创建标志, 接收线程ID)
        // 第四个参数传 NULL，对应 AddCore 里的 lpParameter 接收不到任何数据。
        hThreads[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)AddCore, NULL, 0, NULL);
    }

    // 主线程在这里“死等”，直到数组里的 5 个线程全部执行完毕。
    // 第三个参数 TRUE：表示等待数组中所有的线程（如果为 FALSE，只要有一个线程结束就会返回）。
    WaitForMultipleObjects(5, hThreads, TRUE, INFINITE);

    // 打扫战场：关闭线程句柄和互斥体句柄，释放系统资源
    for (int i = 0; i < 5; i++) {
        if(hThreads[i])
            CloseHandle(hThreads[i]);
    }
    CloseHandle(hMutex);
	std::cout << Count;
}

