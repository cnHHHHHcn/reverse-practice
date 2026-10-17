#include <stdio.h>

/* ============================================================
 * 1. 普通递归 (递归调用 + 非尾调用)
 *    递归调用之后还有乘法操作,所以不是尾调用
 *    factorial(5) 需要保留 5 层栈帧
 * ============================================================ */
long factorial_recursive(int n)
{
    if (n <= 1) return 1;              /* 基准情形 */
    return n * factorial_recursive(n - 1);  /* 调用返回后还要乘 n,非尾调用 */
}

/* ============================================================
 * 2. 尾递归 (递归调用是函数最后一步操作)
 *    用累加器 acc 把"待办计算"提前完成
 *    理论上可被编译器优化为循环 (尾调用优化 TCO)
 * ============================================================ */
long factorial_tail(int n, long acc)
{
    if (n <= 1) return acc;            /* 基准情形直接返回累加器 */
    return factorial_tail(n - 1, n * acc);  /* 递归调用是最后一步 → 尾调用 */
}

/* 对外接口,隐藏累加器参数 */
long factorial(int n)
{
    return factorial_tail(n, 1);
}

/* ============================================================
 * 3. 普通调用 vs 尾调用 的栈示意
 *    下面用求和再演示一次,并打印调用过程
 * ============================================================ */

 /* 非尾递归求和:sum(n-1) 返回后还要 + n */
int sum_recursive(int n)
{
    if (n == 0) return 0;
    return n + sum_recursive(n - 1);   /* 非尾调用 */
}

/* 尾递归求和:acc 携带结果,调用在末尾 */
int sum_tail(int n, int acc)
{
    if (n == 0) return acc;
    return sum_tail(n - 1, acc + n);   /* 尾调用 */
}

/* ============================================================
 * 4. 尾调用(不一定是递归)示例
 *    f 的最后一句直接 return g(x); 这是尾调用
 * ============================================================ */
int g(int x)
{
    return x * 2;
}

int f(int x)
{
    return g(x);        /* 尾调用:g 返回后 f 不做任何事 */
}

int f_non_tail(int x)
{
    return g(x) + 1;    /* 非尾调用:g 返回后还要 +1 */
}

int main(void)
{
    printf("=== 阶乘 ===\n");
    printf("factorial_recursive(5) = %ld\n", factorial_recursive(5));
    printf("factorial_tail(5, 1)   = %ld\n", factorial_tail(5, 1));
    printf("factorial(5)           = %ld\n", factorial(5));

    printf("\n=== 求和 ===\n");
    printf("sum_recursive(5) = %d\n", sum_recursive(5));
    printf("sum_tail(5, 0)   = %d\n", sum_tail(5, 0));

    printf("\n=== 尾调用 vs 非尾调用 ===\n");
    printf("f(10)          = %d  (尾调用)\n", f(10));
    printf("f_non_tail(10) = %d  (非尾调用)\n", f_non_tail(10));

    return 0;
}