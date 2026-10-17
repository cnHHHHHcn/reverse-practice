// 若代码中的数据在编译期已经确定，相关分支即等同于死代码；编译器可据此进行预测与优化，以缩减生成文件的体积。
// 仅在本文件中展示编译器优化效果，其他文件不展示。

#include <iostream>

void if_Single_Branch();
void if_Double_Branch();
void if_Mulit_Branch();
void switch_Multi_Branch();

int main() {
	if_Single_Branch();
	if_Double_Branch();
	if_Mulit_Branch();
	switch_Multi_Branch();
}

 void if_Single_Branch() {
	int a = 1;
	if (a != 0) {
		printf("a is not Zero.\r\n");
	}
}

void if_Double_Branch() {
	int a = 10;
	int b = 20;
	if (a < b) {
		printf("a < b\r\n");
	}
	else {
		printf("a > b\r\n");
	}
}


void if_Mulit_Branch() {
	int Score = 78;
	if (Score >= 90) {
		printf("Grade A\n");
	}
	else if (Score >= 80) {
		printf("Grade B\n");
	}
	else if (Score >= 70) {
		printf("Grade C\n");
	}
	else if (Score >= 60) {
		printf("Grade D\n");
	}
	else {
		printf("Grade F\n");
	}
}

void switch_Multi_Branch() {
	int Score = 78;
	switch (Score / 10) {
	case 10:
	case 9:
		printf("Grade A\n");
		break;
	case 8:
		printf("Grade B\n");
		break;
	case 7:
		printf("Grade C\n");
		break;
	case 6:
		printf("Grade D\n");
		break;
	default:
		printf("Grade F\n");
		break;
	}
}

// 项目配置属性 -> C/C++ -> 优化(<不同选项>)
// Asm x86
/*
 * .text:00401040 ; int __cdecl main()
 * .text:00401040 _main           proc near               ; CODE XREF: __scrt_common_main_seh+F8↓p
 * .text:00401040                 push    offset _Format  ; "a is not Zero.\r\n"
 * .text:00401045                 call    _printf
 * .text:0040104A                 push    offset aAB      ; "a < b\r\n"
 * .text:0040104F                 call    _printf
 * .text:00401054                 push    offset aGradeC  ; "Grade C\n"
 * .text:00401059                 call    _printf
 * .text:0040105E                 push    offset aGradeC  ; "Grade C\n"
 * .text:00401063                 call    _printf
 * .text:00401068                 add     esp, 10h
 * .text:0040106B                 xor     eax, eax
 * .text:0040106D                 retn
 * .text:0040106D _main           endp
 */

// Asm x64
/*
 * .text:0000000140001070 ; int __fastcall main(int argc, const char **argv, const char **envp)
 * .text:0000000140001070 main            proc near               ; CODE XREF: __scrt_common_main_seh+107↓p
 * .text:0000000140001070                                         ; DATA XREF: .pdata:000000014000400C↓o
 * .text:0000000140001070                 sub     rsp, 28h
 * .text:0000000140001074                 lea     rcx, _Format    ; "a is not Zero.\r\n"
 * .text:000000014000107B                 call    printf
 * .text:0000000140001080                 lea     rcx, aAB        ; "a < b\r\n"
 * .text:0000000140001087                 call    printf
 * .text:000000014000108C                 lea     rcx, aGradeC    ; "Grade C\n"
 * .text:0000000140001093                 call    printf
 * .text:0000000140001098                 lea     rcx, aGradeC    ; "Grade C\n"
 * .text:000000014000109F                 call    printf
 * .text:00000001400010A4                 xor     eax, eax
 * .text:00000001400010A6                 add     rsp, 28h
 * .text:00000001400010AA                 retn
 * .text:00000001400010AA main            endp
 */
