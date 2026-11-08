#include <cstdio>

template <typename Type>
Type Add(Type Param1, Type Param2) {
	return Param1 + Param2;
}

int main() {

	void* FuncAddress = nullptr;
	FuncAddress = Add<unsigned char>;
	printf("%p unsigned char\n", FuncAddress);

	FuncAddress = Add<char>;
	printf("%p char\n", FuncAddress);

	FuncAddress = Add<unsigned short>;
	printf("%p unsigned short\n", FuncAddress);

	FuncAddress = Add<short>;
	printf("%p short\n", FuncAddress);

	FuncAddress = Add<unsigned int>;
	printf("%p unsigned int\n", FuncAddress);

	FuncAddress = Add<int>;
	printf("%p int\n", FuncAddress);

	FuncAddress = Add<unsigned long>;
	printf("%p unsigned long\n", FuncAddress);

	FuncAddress = Add<long>;
	printf("%p long\n", FuncAddress);

	FuncAddress = Add<unsigned long long>;
	printf("%p unsigned long long\n", FuncAddress);

	FuncAddress = Add<long long>;
	printf("%p long long\n", FuncAddress);

	FuncAddress = Add<float>;
	printf("%p float\n", FuncAddress);

	FuncAddress = Add<double>;
	printf("%p double\n", FuncAddress);

	printf("end");
}