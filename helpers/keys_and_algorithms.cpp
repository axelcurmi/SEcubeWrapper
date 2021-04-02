#include <stdlib.h>
#include <stdio.h>

#include "../SEcubeSources/L1/L1.h"

static uint8_t pin[32] = {
    't','e','s','t', 0,0,0,0, 0,0,0,0, 0,0,0,0,
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0
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
    l1.L1Login(pin, SE3_ACCESS_USER, true);

    uint16_t skip  = 0;
    uint16_t count = 0;

    // Keys
    uint16_t maxKeys = 32;
    se3Key keyArray[maxKeys];
    memset(keyArray, 0, sizeof(se3Key) * maxKeys);

    l1.L1KeyList(maxKeys, skip, keyArray, &count);
    printf("Key List:\n");
    for (uint16_t i = 0; i < count; i++)
    {
        printf("  [%d] %s\n", i, keyArray[i].name);
    }

    // Algorithms
    uint16_t maxAlgos = 32;
    se3Algo algoArray[maxAlgos];
    memset(algoArray, 0, sizeof(se3Algo) * maxAlgos);

    l1.L1GetAlgorithms(maxAlgos, skip, algoArray, &count);
    printf("Algorithm List:\n");
    for (uint16_t i = 0; i < count; i++)
    {
        char *type;
        switch (algoArray[i].type)
        {
            case L1Crypto::CryptoTypes::SE3_CRYPTO_TYPE_BLOCKCIPHER:
            {
                type = (char *)"block cipher";
                break;
            }
            case L1Crypto::CryptoTypes::SE3_CRYPTO_TYPE_BLOCKCIPHER_AUTH:
            {
                type = (char *)"block cipher with auth";
                break;
            }
            case L1Crypto::CryptoTypes::SE3_CRYPTO_TYPE_STREAMCIPHER:
            {
                type = (char *)"stream cipher";
                break;
            }
            case L1Crypto::CryptoTypes::SE3_CRYPTO_TYPE_DIGEST:
            {
                type = (char *)"digest";
                break;
            }
            case L1Crypto::CryptoTypes::SE3_CRYPTO_TYPE_OTHER:
            {
                type = (char *)"other";
                break;
            }
            default:
            {
                type = (char *)"unknown";
                break;
            }
        }

        printf("  [%d] %s (%s)\n", i, algoArray[i].name, type);
    }

    l1.L1Logout();
    l0.L0Close();

    return EXIT_SUCCESS;
}
