#include <stdio.h>
#include <setjmp.h>
#include <string.h>

// 定义"异常上下文"
static jmp_buf exception_env;

// 模拟异常码
typedef enum {
    OK = 0,
    ERR_DIV_ZERO,
    ERR_NULL_PTR,
    ERR_OUT_OF_RANGE
} ErrCode;

const char* err_msg(ErrCode code) {
    switch (code) {
    case ERR_DIV_ZERO:     return "除零错误";
    case ERR_NULL_PTR:     return "空指针访问";
    case ERR_OUT_OF_RANGE: return "数组越界";
    default:               return "未知错误";
    }
}

// 模拟可能"抛异常"的函数
int safe_div(int a, int b) {
    if (b == 0) {
        longjmp(exception_env, ERR_DIV_ZERO);  // 抛出异常
    }
    return a / b;
}

void check_ptr(const void* p) {
    if (p == NULL) {
        longjmp(exception_env, ERR_NULL_PTR);  // 抛出异常
    }
}

int access_array(int* arr, int len, int idx) {
    if (idx < 0 || idx >= len) {
        longjmp(exception_env, ERR_OUT_OF_RANGE);
    }
    return arr[idx];
}

int main(void) {
    // setjmp 第一次返回 0 表示"进入 try 块"
    int exc = setjmp(exception_env);

    if (exc == 0) {
        // ---- 相当于 try 块 ----
        printf("开始执行...\n");

        printf("10 / 2 = %d\n", safe_div(10, 2));

        int* p = NULL;
        check_ptr(p);                 // 这里会抛出 ERR_NULL_PTR

        printf("这行不会执行\n");
    }
    else {
        // ---- 相当于 catch 块 ----
        printf("捕获到异常: [%d] %s\n", exc, err_msg((ErrCode)exc));
    }

    printf("程序继续正常执行\n");
    return 0;
}