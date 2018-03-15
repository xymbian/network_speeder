#include "network_util.h"

static size_t total_case;
static size_t fail_case;
static size_t success_case;

#define TOTAL_COUNT total_case++
#define FIAL_COUNT fail_case++
#define VERIFY_EQUAL(a, b) a == b ? success_case++ : (fail_case++, printf("Failed case: %s, Line: %d\n", __FUNCTION__, __LINE__))
#define VERIFY_NOT_EQUAL(a, b) a != b ? success_case++ : (fail_case++, printf("Failed case: %s, Line: %d\n", __FUNCTION__, __LINE__))

void case_1()
{
    TOTAL_COUNT;

    uint8 data[] = {0x45};
    uint16 checkSum = internet_checksum(data, sizeof(data));
    uint16 expect = ~0x4500;
    uint16 noExpect = 0x4500;

    VERIFY_EQUAL(checkSum, expect);
    VERIFY_NOT_EQUAL(checkSum, noExpect);
}

void case_2()
{
    TOTAL_COUNT;

    uint8 data[] = {0x45, 0x00};
    uint16 checkSum = internet_checksum(data, sizeof(data));
    uint16 expect = ~0x4500;
    uint16 noExpect = 0x4500;

    VERIFY_EQUAL(checkSum, expect);
    VERIFY_NOT_EQUAL(checkSum, noExpect);
}

void case_3()
{
    TOTAL_COUNT;

    uint8 data[] = {0x45, 0x00, 0x00};
    uint16 checkSum = internet_checksum(data, sizeof(data));
    uint16 expect = ~0x4500;
    uint16 noExpect = 0x4500;

    VERIFY_EQUAL(checkSum, expect);
    VERIFY_NOT_EQUAL(checkSum, noExpect);
}

void case_4()
{
    TOTAL_COUNT;

    uint8 data[] = {0xff};
    uint16 checkSum = internet_checksum(data, sizeof(data));
    uint16 expect = 0x00ff;
    uint16 noExpect = 0x00;

    VERIFY_EQUAL(checkSum, expect);
    VERIFY_NOT_EQUAL(checkSum, noExpect);
}

void case_5()
{
    TOTAL_COUNT;

    uint8 data[] = {0xff, 0x00, 0x00};
    uint16 checkSum = internet_checksum(data, sizeof(data));
    uint16 expect = 0x00ff;
    uint16 noExpect = 0x00;

    VERIFY_EQUAL(checkSum, expect);
    VERIFY_NOT_EQUAL(checkSum, noExpect);
}

void case_6()
{
    TOTAL_COUNT;

    uint8 data[] = {0xff, 0xff};
    uint16 checkSum = internet_checksum(data, sizeof(data));
    uint16 expect = 0x00;
    uint16 noExpect = 0xffff;

    VERIFY_EQUAL(checkSum, expect);
    VERIFY_NOT_EQUAL(checkSum, noExpect);
}

void case_7()
{
    TOTAL_COUNT;

    uint8 data[] = {0xff, 0xff, 0xff, 0x00};
    uint16 checkSum = internet_checksum(data, sizeof(data));
    uint16 expect = 0x00ff;
    uint16 noExpect = 0xff00;

    VERIFY_EQUAL(checkSum, expect);
    VERIFY_NOT_EQUAL(checkSum, noExpect);
}

int main(int argc, char* argv[])
{
    case_1();
    case_2();
    case_3();
    case_4();
    case_5();
    case_6();
    case_7();

    printf("Test result: Tatol(%lu)/Fail(%lu)\n", total_case, fail_case);
    return 0;
}

