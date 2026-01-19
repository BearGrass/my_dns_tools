#include<stdio.h>
#define LOG_FF 12
#define ALOG(x) printf("%d\n",LOG_##x);
int main()
{
    ALOG(FF);
    return 0;
}
