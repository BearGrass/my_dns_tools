#include<stdio.h>
#define ORG(x) x
#define STR(x) #x
#define _STR(x) str_##x

#define SS(x) _STR(@#x)

#define HEAP(x) _HEAP(x)
void main()
{
    int j = 1;
    printf("%s\n", _STR(STR(ORG(j))));
}
