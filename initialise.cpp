#include <stdlib.h>
#include <stdio.h>

#include "SEcubeSources/L1/L1.h"

static uint8_t pin_test[32] = {
    't','e','s','t', 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
};

static uint8_t pin0[32] = {
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
};

static uint8_t test_sn[32] = {
    1,2,3,4, 5,6,7,8, 1,2,3,4, 5,6,7,8,
    8,7,6,5, 4,3,2,1, 8,7,6,5, 4,3,2,1
};

int main()
{
    printf("Searching for SEcube(s)\n");
    L0 l0 = L0();

    uint8_t numDevices = l0.GetNumberDevices();
    if (numDevices == 0)
    {
        printf("No devices connected!\n");
        return EXIT_FAILURE;
    }
    printf("Device Found!\n");

    L1 l1 = L1();

    l1.L1FactoryInit(test_sn);

    try
    {
        l1.L1Login(pin0, SE3_ACCESS_ADMIN, true);
    }
    catch(...)
    {
        printf("SEcube already initialized!\n");
        return EXIT_FAILURE;
    }

    l1.L1SetUserPIN(pin_test);
    l1.L1SetAdminPIN(pin_test);
    printf("User PIN set to \"test\" succesfully\n");
    printf("Admin PIN set to \"test\" succesfully\n");

    l1.L1Logout();
    l0.L0Close();

    printf("Initialization completed Successfully\n");
    return EXIT_SUCCESS;
}
