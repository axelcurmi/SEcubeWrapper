#ifndef _L1_WRAPPER_H
#define _L1_WRAPPER_H

#include <stdint.h>

extern "C"
{
    struct L1_handle;
    typedef struct L1_handle L1_handle_t;

    L1_handle_t *L1_Create();
    void L1_Destroy(L1_handle_t *l1);

    int8_t L1_Login(L1_handle_t *l1, const uint8_t *pin, uint16_t access,
                    bool force);
    int8_t L1_Logout(L1_handle_t *l1);

    int8_t L1_CryptoSetTimeNow(L1_handle_t *l1);
    int8_t L1_CryptoInit(L1_handle_t *l1, uint16_t algorithm, uint16_t mode,
                         uint32_t keyID, uint32_t* sessionID);
    int8_t L1_CryptoUpdate(L1_handle_t *l1, uint32_t sessionID, uint16_t flags,
                           uint16_t dataInLen, uint8_t* dataIn,
                           uint16_t* dataOutLen, uint8_t* dataOut);

    int8_t L1_Encrypt(L1_handle_t *l1, size_t dataInLen, uint8_t* dataIn,
                      size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm,
                      uint16_t mode, uint32_t keyID);
    int8_t L1_Decrypt(L1_handle_t *l1, size_t dataInLen, uint8_t* dataIn,
                      size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm,
                      uint16_t mode, uint32_t keyID);
}

#endif // !_L1_WRAPPER_H
