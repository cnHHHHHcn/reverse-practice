#define _CRT_SECURE_NO_WARNINGS
#include <iostream>

void print1To10();
void sum1To100();
void multiplicationTable();
void isPrime();
void printDivisibleBy3();
void menuDemo(); 

int main() {
    print1To10();
    sum1To100();
    multiplicationTable();
    isPrime();
    printDivisibleBy3();
    menuDemo();
	return 0;
}

void print1To10() {
    for (int i = 1; i <= 10; i++) {
        printf("%d ", i);
    }
    printf("\n");
}

void sum1To100() {
    int sum = 0;
    for (int i = 1; i <= 100; i++) {
        sum += i;
    }
    printf("1~100 的和 = %d\n", sum);
}

void multiplicationTable() {
    for (int i = 1; i <= 9; i++) {
        for (int j = 1; j <= i; j++) {
            printf("%d*%d=%d\t", j, i, i * j);
        }
        printf("\n");
    }
}

void isPrime() {
    int n;
    int rtn;
    printf("输入一个正整数：");
    rtn = scanf("%d", &n);

    bool isPrime = (n > 1);
    for (int i = 2; i <= (int)sqrt(n); i++) {
        if (n % i == 0) {
            isPrime = false;
            break;
        }
    }
    printf("%d %s\n", n, isPrime ? "是素数" : "不是素数");
}

void printDivisibleBy3() {
    for (int i = 1; i <= 100; i++) {
        if (i % 3 != 0) continue;
        printf("%d ", i);
    }
    printf("\n");
}

void menuDemo() {
    int choice;
    int rtn;
    do {
        printf("==== 菜单 ====\n");
        printf("1. 开始游戏\n");
        printf("2. 查看说明\n");
        printf("0. 退出\n");
        printf("请选择：");
        rtn = scanf("%d", &choice);

        switch (choice) {
        case 1: printf("游戏开始！\n"); break;
        case 2: printf("这是说明……\n"); break;
        case 0: printf("再见！\n"); break;
        default: printf("无效选择\n");
        }
    } while (choice != 0);
}

