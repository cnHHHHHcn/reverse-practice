#include <iostream>
#include <vector>
#include <memory>
#include <string>
#include <algorithm>
#include <typeinfo>

using std::cout;
using std::endl;
using std::string;
using std::vector;
using std::unique_ptr;
using std::make_unique;

// ===================== 抽象基类 =====================
class Animal {
public:
    // 构造函数
    Animal(const string& name, int age)
        : name_(name), age_(age) {
        cout << "[构造] Animal: " << name_ << endl;
    }

    // 虚析构：保证通过基类指针 delete 派生对象时能正确析构
    virtual ~Animal() {
        cout << "[析构] Animal: " << name_ << endl;
    }

    // 纯虚函数：Animal 本身不能实例化
    virtual void speak() const = 0;

    // 普通虚函数：派生类可重写
    virtual string category() const {
        return "Animal";
    }

    // 非虚函数：不参与多态
    void showBasic() const {
        cout << "  名字=" << name_ << ", 年龄=" << age_ << endl;
    }

    string getName() const { return name_; }
    int    getAge()  const { return age_; }

protected:
    string name_;
    int    age_;
};

// ===================== 派生类：Dog =====================
class Dog : public Animal {
public:
    Dog(const string& name, int age, const string& breed)
        : Animal(name, age), breed_(breed) {
        cout << "[构造] Dog: " << name_ << " (" << breed_ << ")" << endl;
    }

    ~Dog() override {
        cout << "[析构] Dog: " << name_ << endl;
    }

    void speak() const override {
        cout << "  " << name_ << " 汪汪汪！" << endl;
    }

    string category() const override { return "Dog"; }

private:
    string breed_;   // 品种
};

// ===================== 派生类：Cat =====================
class Cat : public Animal {
public:
    Cat(const string& name, int age)
        : Animal(name, age) {
        cout << "[构造] Cat: " << name_ << endl;
    }

    ~Cat() override {
        cout << "[析构] Cat: " << name_ << endl;
    }

    void speak() const override {
        cout << "  " << name_ << " 喵喵喵~" << endl;
    }

    string category() const override { return "Cat"; }
};

// ===================== 派生类：Bird =====================
class Bird : public Animal {
public:
    Bird(const string& name, int age, bool canFly)
        : Animal(name, age), canFly_(canFly) {
        cout << "[构造] Bird: " << name_ << endl;
    }

    ~Bird() override {
        cout << "[析构] Bird: " << name_ << endl;
    }

    void speak() const override {
        cout << "  " << name_ << " 啾啾啾！" << endl;
    }

    string category() const override { return "Bird"; }

private:
    bool canFly_;
};

// ===================== 工具：分隔线 =====================
void line(const string& title) {
    cout << "\n========== " << title << " ==========" << endl;
}

// ===================== main =====================
int main() {
    // ---------- 1. 构造：创建对象放入 vector ----------
    line("1. 构造对象并加入 vector");
    vector<unique_ptr<Animal>> zoo;
    zoo.push_back(make_unique<Dog>("旺财", 3, "柴犬"));
    zoo.push_back(make_unique<Cat>("咪咪", 2));
    zoo.push_back(make_unique<Bird>("小蓝", 1, true));
    zoo.push_back(make_unique<Dog>("大黄", 5, "金毛"));

    // ---------- 2. 多态：虚函数调用 ----------
    line("2. 多态调用 speak()");
    for (const auto& a : zoo) {
        a->speak();           // 通过基类指针调用派生实现
    }

    // ---------- 3. 虚表观察 ----------
    line("3. 虚表(vtable)与 typeid 观察");
    for (const auto& a : zoo) {
        cout << "对象真实类型: " << typeid(*a).name()
            << ", category()=" << a->category() << endl;
    }
    cout << "sizeof(Animal)=" << sizeof(Animal)
        << " (含 8 字节 vptr，指向虚表)" << endl;

    // ---------- 4. STL 算法：排序、查找、计数 ----------
    line("4. STL 算法");
    // 按年龄排序
    std::sort(zoo.begin(), zoo.end(),
        [](const unique_ptr<Animal>& x,
            const unique_ptr<Animal>& y) {
                return x->getAge() < y->getAge();
        });
    cout << "按年龄升序：" << endl;
    for (const auto& a : zoo) {
        cout << "  " << a->getName() << " (" << a->getAge() << "岁)" << endl;
    }

    // 查找名字含"旺"的
    auto it = std::find_if(zoo.begin(), zoo.end(),
        [](const unique_ptr<Animal>& a) {
            return a->getName().find("旺") != string::npos;
        });
    if (it != zoo.end()) {
        cout << "找到名字含'旺'的动物：" << (*it)->getName() << endl;
    }

    // 统计各类型数量
    int dogs = std::count_if(zoo.begin(), zoo.end(),
        [](const unique_ptr<Animal>& a) {
            return dynamic_cast<Dog*>(a.get()) != nullptr;
        });
    cout << "狗的数量：" << dogs << endl;

    // ---------- 5. 拷贝构造 / 移动构造 ----------
    line("5. 拷贝构造 vs 移动构造");
    Dog d1("复制狗", 1, "泰迪");
    Dog d2 = d1;                  // 拷贝构造
    Dog d3 = std::move(d1);       // 移动构造
    cout << "d2=" << d2.getName() << ", d3=" << d3.getName() << endl;

    // ---------- 6. 析构顺序演示 ----------
    line("6. 局部对象析构（离开作用域自动触发）");
    {
        Cat tmp("临时猫", 0);
    } // tmp 在此析构

    // ---------- 7. zoo 清空时析构顺序 ----------
    line("7. 清空 zoo（逆序析构）");
    zoo.clear();   // 每个 unique_ptr 释放，触发虚析构

    line("main 结束");
    return 0;
}