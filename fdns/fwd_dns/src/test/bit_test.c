#nclude"bit.h"
int main()
{
    uint8_t bitmap[20];
    set_all_bit(bitmap, 0, sizeof(bitmap));
    set_bit(bitmap, 100);
    set_bit(bitmap, 11);
    uint8_t i = 0;
    for (i = 0; i < 160; i++) {
        if (find_bit(bitmap, i))
            printf("%u set \n", i);
    }

    clean_bit(bitmap, 10);
    clean_bit(bitmap, 11);
    for (i = 0; i < 160; i++) {
        if (find_bit(bitmap, i))
            printf("%u set \n", i);
    }
    return 0;
}
