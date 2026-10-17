#include <iostream>
#include <stdexcept>
#include <string>

// 自定义异常类：继承 std::exception
class DivZeroError : public std::exception {
public:
    const char* what() const noexcept override {
        return "除零错误";
    }
};

class NullPtrError : public std::runtime_error {
public:
    NullPtrError() : std::runtime_error("空指针访问") {}
};

// 可能抛异常的函数
int safe_div(int a, int b) {
    if (b == 0) throw DivZeroError();      // 抛出异常
    return a / b;
}

void check_ptr(const void* p) {
    if (p == nullptr) throw NullPtrError();
}

int main() {
    try {
        std::cout << "开始执行...\n";

        std::cout << "10 / 2 = " << safe_div(10, 2) << "\n";

        int* p = nullptr;
        check_ptr(p);                       // 这里抛出 NullPtrError

        std::cout << "这行不会执行\n";
    }
    catch (const DivZeroError& e) {
        std::cout << "捕获到异常: " << e.what() << "\n";
    }
    catch (const std::exception& e) {       // 兜底：捕获所有标准异常
        std::cout << "捕获到异常: " << e.what() << "\n";
    }

    std::cout << "程序继续正常执行\n";
    return 0;
}