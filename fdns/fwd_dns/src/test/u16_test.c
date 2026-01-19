#include<stdint.h>
#include<stdio.h>
#include<string.h>
int main()
{
    uint16_t i = 123;
    uint16_t b;
    memcpy(&b, &i, 2);
    printf("b=%d\n", b);
    return 0;
}
