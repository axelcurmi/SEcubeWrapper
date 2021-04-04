#ifndef _L1_WRAPPER_H
#define _L1_WRAPPER_H

#include <stdint.h>

#define SHA256_KEY_ID 0xFFFFFFFF

#ifdef __cplusplus
extern "C"
{
#endif

struct L1_handle;
typedef struct L1_handle L1_handle_t;

L1_handle_t *L1_Create();
void L1_Destroy(L1_handle_t *l1);

int8_t L1_Login(L1_handle_t *l1, const uint8_t *pin, uint16_t access,
    uint8_t force);
int8_t L1_Logout(L1_handle_t *l1);

int8_t L1_FindKey(L1_handle_t *l1, uint32_t keyID);
int8_t L1_KeyEdit(L1_handle_t *l1, uint32_t id, uint32_t validity,
    uint16_t dataSize, uint16_t nameSize, uint8_t* data, uint8_t* name,
    uint16_t op);

int8_t L1_CryptoSetTimeNow(L1_handle_t *l1);

int8_t CryptoInit(L1_handle_t *l1, uint16_t algorithm, uint16_t flags,
    uint32_t keyId, uint32_t* sessionId);
int8_t CryptoUpdate(L1_handle_t *l1, uint32_t sessionId, uint16_t flags,
    uint16_t data1Len, uint8_t* data1, uint16_t data2Len, uint8_t* data2,
    uint16_t* dataOutLen, uint8_t* dataOut);

int8_t DigestSHA256(L1_handle_t *l1, uint16_t dataInLen, uint8_t *dataIn,
    uint16_t *dataOutLen, uint8_t *dataOut);
int8_t DigestHMACSHA256(L1_handle_t *l1, uint32_t keyId,
    uint16_t dataInLen, uint8_t *dataIn, uint16_t *dataOutLen,
    uint8_t *dataOut);

#ifdef __cplusplus
}
#endif

#endif // !_L1_WRAPPER_H
