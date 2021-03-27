#ifndef _L1_WRAPPER_H
#define _L1_WRAPPER_H

#include <stdint.h>

#define SHA256_KEY_ID 0xFFFFFFFF

extern "C"
{
    struct L1_handle;
    typedef struct L1_handle L1_handle_t;

    L1_handle_t *L1_Create();
    void L1_Destroy(L1_handle_t *l1);

    int8_t L1_Login(L1_handle_t *l1, const uint8_t *pin, uint16_t access,
                    bool force);
    int8_t L1_Logout(L1_handle_t *l1);

    int8_t L1_FindKey(L1_handle_t *l1, uint32_t keyID);
    int8_t L1_KeyEdit(L1_handle_t *l1, se3Key* key, uint16_t op);

    int8_t L1_CryptoSetTimeNow(L1_handle_t *l1);

    int8_t SHA256_digest(L1_handle_t *l1, uint16_t dataInLen, uint8_t *dataIn,
                         uint16_t *dataOutLen, uint8_t *dataOut);
    int8_t Encrypt(L1_handle_t *l1, uint16_t algorithm, uint16_t mode,
                   uint32_t keyID, uint16_t dataInLen, uint8_t *dataIn,
                   uint16_t IVLen, uint8_t *IV, uint16_t *dataOutLen,
                   uint8_t *dataOut);

    // int8_t L1_Encrypt(L1_handle_t *l1, size_t dataInLen, uint8_t* dataIn,
    //                   size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm,
    //                   uint16_t mode, uint32_t keyID);
    // int8_t L1_Decrypt(L1_handle_t *l1, size_t dataInLen, uint8_t* dataIn,
    //                   size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm,
    //                   uint16_t mode, uint32_t keyID);
    // int8_t L1_Digest(L1_handle_t *l1, size_t dataInLen, uint8_t* dataIn,
    //                 size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm);
}

#endif // !_L1_WRAPPER_H
