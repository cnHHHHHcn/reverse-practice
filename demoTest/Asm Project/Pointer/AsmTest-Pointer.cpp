#define _CRT_SECURE_NO_WARNINGS

#include <cstdio>
#include <cstring>

#define MAX 100          // 最多 100 个学生

// ===================== 结构体定义 =====================
struct Student {
    char name[20];       // 姓名
    int  id;             // 学号
    float score;         // 成绩
};

// ===================== 函数声明 =====================
void printMenu();
void addStudent(Student* arr, int* count);          // 指针 + 指针
void printAll(const Student* arr, int count);       // 只读指针
void findByName(Student* arr, int count);
void sortByScore(Student* arr, int count);
void printAverage(const Student* arr, int count);

// ===================== 主函数 =====================
int main() {
    Student students[MAX];   // 结构体数组
    int count = 0;           // 当前学生数量
    int choice;

    do {
        printMenu();
        printf("请选择：");
        scanf("%d", &choice);

        switch (choice) {
        case 1: addStudent(students, &count);      break;
        case 2: printAll(students, count);         break;
        case 3: findByName(students, count);       break;
        case 4: sortByScore(students, count);      break;
        case 5: printAverage(students, count);     break;
        case 0: printf("再见！\n");                break;
        default: printf("无效选择！\n");
        }
        printf("\n");
    } while (choice != 0);

    return 0;
}

// ===================== 打印菜单 =====================
void printMenu() {
    printf("======== 学生成绩管理 ========\n");
    printf("1. 添加学生\n");
    printf("2. 显示全部\n");
    printf("3. 按姓名查找\n");
    printf("4. 按成绩排序\n");
    printf("5. 计算平均分\n");
    printf("0. 退出\n");
    printf("==============================\n");
}

// ===================== 添加学生 =====================
// arr: 指向结构体数组首元素；count: 指向数量的指针
void addStudent(Student* arr, int* count) {
    if (*count >= MAX) {
        printf("学生已满，无法添加！\n");
        return;
    }

    Student* p = arr + *count;    // 指针指向下一个空位

    printf("姓名：");
    scanf("%19s", p->name);
    printf("学号：");
    scanf("%d", &p->id);
    printf("成绩：");
    scanf("%f", &p->score);

    (*count)++;                   // 数量 +1
    printf("添加成功！\n");
}

// ===================== 显示全部 =====================
void printAll(const Student* arr, int count) {
    if (count == 0) {
        printf("暂无学生！\n");
        return;
    }

    printf("%-10s %-8s %-6s\n", "姓名", "学号", "成绩");
    const Student* p = arr;           // 用指针遍历
    const Student* end = arr + count; // 尾后指针
    for (; p < end; ++p) {
        printf("%-10s %-8d %-6.1f\n", p->name, p->id, p->score);
    }
}

// ===================== 按姓名查找 =====================
void findByName(Student* arr, int count) {
    char target[20];
    printf("输入要查找的姓名：");
    scanf("%19s", target);

    Student* p = arr;
    Student* end = arr + count;
    while (p < end) {
        if (strcmp(p->name, target) == 0) {
            printf("找到：%s  学号 %d  成绩 %.1f\n",
                p->name, p->id, p->score);
            return;
        }
        ++p;
    }
    printf("未找到 %s\n", target);
}

// ===================== 按成绩排序（冒泡） =====================
void sortByScore(Student* arr, int count) {
    if (count < 2) {
        printf("数据不足，无需排序。\n");
        return;
    }

    for (int i = 0; i < count - 1; i++) {
        for (int j = 0; j < count - 1 - i; j++) {
            Student* a = arr + j;
            Student* b = arr + j + 1;
            if (a->score < b->score) {   // 按成绩降序
                Student tmp = *a;        // 结构体整体交换
                *a = *b;
                *b = tmp;
            }
        }
    }
    printf("排序完成（按成绩降序）。\n");
}

// ===================== 计算平均分 =====================
void printAverage(const Student* arr, int count) {
    if (count == 0) {
        printf("暂无学生！\n");
        return;
    }

    float sum = 0.0f;
    const Student* p = arr;
    const Student* end = arr + count;
    for (; p < end; ++p) {
        sum += p->score;
    }
    printf("共 %d 人，平均分 = %.2f\n", count, sum / count);
}