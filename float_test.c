#include <stdio.h>
#include <stdlib.h>

typedef unsigned int UINT;

typedef struct _floatStruct{
    UINT Mantissa:23;
    UINT Exponent:8;
    UINT Symbol:1;
}floatStruct, *PfloatStruct;


int power(int Base, int n){
    int i = 0, rtn = 1;
    for(i = 0; i < n; i++){
        rtn *= Base;
    }
    return rtn;
}

int main(int argc, char** argv) {
    while(1){
        float test = 0.00;
        printf("Send float Value:");
        scanf("%f", &test);
        
        // 这里的强转在 x86 下是可行的
        int* ptest = (int*)&test;
        PfloatStruct pDisplay = (PfloatStruct)ptest;

        // 1. 打印原始数据
        printf("Input: %f\n", test);
        printf("Raw Hex: 0x%X\n", *ptest);
        printf("S: %d, E: %d, M: %d\n", pDisplay->Symbol, pDisplay->Exponent, pDisplay->Mantissa);

        // 2. 开始复现公式 (必须用 double，不能用 int)
        // 公式: (-1)^S * (1 + M/2^23) * 2^(E-127)
        
        double sign_part = (pDisplay->Symbol == 1) ? -1.0 : 1.0; // 修正符号计算
        
        // 修正尾数计算：必须除以 2^23 变成小数
        double mantissa_part = 1.0 + ((double)pDisplay->Mantissa / 8388608.0); 
        
        // 修正指数计算：使用 pow 支持负指数
        double exp_part = power(2, pDisplay->Exponent - 127); 
        
        double result = sign_part * mantissa_part * exp_part;

        printf("Calculated: %f\n", result);
        printf("------------------------\n");
    }
    return 0;
}
