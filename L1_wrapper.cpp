#include "SEcubeSources/L1/L1.h"
#include "L1_wrapper.h"

#include <stdio.h>

struct L1_handle
{
    void *obj;
};

L1_handle_t *L1_Create()
{
#ifdef DEBUG_LOG
    printf("[DEBUG_LOG] L1_Create\n");
#endif // DEBUG_LOG

    L1_handle_t *l1;
    L1 *obj;

    l1 = (L1_handle_t *)malloc(sizeof(L1_handle));
    obj = new L1();

    l1->obj = obj;
    return l1;
}

void L1_Destroy(L1_handle_t *l1)
{
#ifdef DEBUG_LOG
    printf("[DEBUG_LOG] L1_Destroy\n");
#endif // DEBUG_LOG

    delete (L1 *)l1->obj;
    free(l1);
}

int8_t L1_Login(L1_handle_t *l1, const uint8_t *pin, uint16_t access,
    uint8_t force)
{
#ifdef DEBUG_LOG
    printf("[DEBUG_LOG] L1_Login\n");
#endif // DEBUG_LOG

    L1 *obj = (L1 *)l1->obj;
    try
    {
        obj->L1Login(pin, access, force);
    }
    catch (...)
    {
        return -1;
    }
    return 0;
}

int8_t L1_Logout(L1_handle_t *l1)
{
#ifdef DEBUG_LOG
    printf("[DEBUG_LOG] L1_Logout\n");
#endif // DEBUG_LOG

    L1 *obj = (L1 *)l1->obj;
    try
    {
        obj->L1Logout();
    }
    catch (...)
    {
        return -1;
    }
    return 0;
}

int8_t L1_FindKey(L1_handle_t *l1, uint32_t keyID)
{
#ifdef DEBUG_LOG
    printf("[DEBUG_LOG] L1_FindKey\n");
#endif // DEBUG_LOG

    L1 *obj = (L1 *)l1->obj;
    return obj->L1FindKey(keyID);
}

int8_t L1_KeyEdit(L1_handle_t *l1, uint32_t id, uint32_t validity,
    uint16_t dataSize, uint16_t nameSize, uint8_t* data, uint8_t* name,
    uint16_t op)
{
#ifdef DEBUG_LOG
    printf("[DEBUG_LOG] L1_KeyEdit\n");
    printf("  -> id: %d\n", id);
    printf("  -> validity: %d\n", validity);
    printf("  -> dataSize: %d\n", dataSize);
    printf("  -> nameSize: %d\n", nameSize);
    printf("  -> name: %s\n", name);
    printf("  -> op: %s\n", op);
#endif // DEBUG_LOG

    L1 *obj = (L1 *)l1->obj;

    se3Key key;
    key.id = id;
    key.validity = validity;
    key.dataSize = dataSize;
    key.nameSize = nameSize;
    key.data = data;
    
    if (nameSize > 0)
    {
        memcpy(key.name, name, nameSize > L1Key::Size::MAX_NAME ?
            L1Key::Size::MAX_NAME : nameSize);
    }

    try
    {
        obj->L1KeyEdit(&key, op);
    }
    catch (...)
    {
        return -1;
    }
    return 0;
}

int8_t L1_CryptoSetTimeNow(L1_handle_t *l1)
{
#ifdef DEBUG_LOG
    printf("[DEBUG_LOG] L1_CryptoSetTimeNow\n");
#endif // DEBUG_LOG

    L1 *obj = (L1 *)l1->obj;
    try
    {
        obj->L1CryptoSetTime(time(0));
    }
    catch (...)
    {
        return -1;
    }
    return 0;
}

int8_t CryptoInit(L1_handle_t *l1, uint16_t algorithm, uint16_t flags,
    uint32_t keyId, uint32_t* sessionId)
{
#ifdef DEBUG_LOG
    printf("[DEBUG_LOG] CryptoInit\n");
    printf("  -> algorithm: %d\n", algorithm);
    printf("  -> flags: %d\n", flags);
    printf("  -> keyId: %d\n", keyId);
    printf("  -> sessionId: %d\n", sessionId);
#endif // DEBUG_LOG

    L1 *obj = (L1 *)l1->obj;
    try
    {
        obj->L1CryptoInit(algorithm, flags, keyId, sessionId);
    }
    catch(...)
    {
        return -1;
    }
    return 0;
}

int8_t CryptoUpdate(L1_handle_t *l1, uint32_t sessionId, uint16_t flags,
    uint16_t data1Len, uint8_t* data1, uint16_t data2Len, uint8_t* data2,
    uint16_t* dataOutLen, uint8_t* dataOut)
{
#ifdef DEBUG_LOG
    printf("[DEBUG_LOG] CryptoUpdate\n");
    printf("  -> sessionId: %d\n", sessionId);
    printf("  -> flags: %d\n", flags);
    printf("  -> data1Len: %d\n", data1Len);
    printf("  -> data2Len: %d\n", data2Len);
#endif // DEBUG_LOG

    L1 *obj = (L1 *)l1->obj;
    try
    {
        obj->L1CryptoUpdate(sessionId, flags, data1Len, data1, data2Len, data2,
            dataOutLen, dataOut);
    }
    catch(...)
    {
        return -1;
    }
    return 0;
}

int8_t DigestSHA256(L1_handle_t *l1, uint16_t dataInLen, uint8_t *dataIn,
    uint16_t *dataOutLen, uint8_t *dataOut)
{
#ifdef DEBUG_LOG
    printf("[DEBUG_LOG] DigestSHA256\n");
    printf("  -> dataInLen: %d\n", dataInLen);
#endif // DEBUG_LOG

    L1 *obj = (L1 *)l1->obj;
    try
    {
        // Create session
        uint32_t sessionID;
        obj->L1CryptoInit(L1Algorithms::Algorithms::SHA256, 0, SHA256_KEY_ID,
            &sessionID);

        // SHA256 Update
        uint16_t chunkLen = dataInLen < L1Crypto::UpdateSize::DATAIN ? 
            dataInLen : L1Crypto::UpdateSize::DATAIN;
        while (dataInLen > 0)
        {
            obj->L1CryptoUpdate(sessionID, 0, chunkLen, dataIn, 0, NULL,
                NULL, NULL);
            
            dataIn += chunkLen;
            dataInLen -= chunkLen;
        }

        // FINIT
        obj->L1CryptoUpdate(sessionID, L1Crypto::UpdateFlags::FINIT, 0, NULL,
            0, NULL, dataOutLen, dataOut);
    }
    catch(...)
    {
        return -1;
    }
    
    return 0;
}

int8_t DigestHMACSHA256(L1_handle_t *l1, uint32_t keyId, uint16_t dataInLen,
    uint8_t *dataIn, uint16_t *dataOutLen, uint8_t *dataOut)
{
#ifdef DEBUG_LOG
    printf("[DEBUG_LOG] DigestHMACSHA256\n");
    printf("  -> keyId: %d\n", keyId);
    printf("  -> dataInLen: %d\n", dataInLen);
#endif // DEBUG_LOG

    L1 *obj = (L1 *)l1->obj;
    try
    {
        // Create session
        uint32_t sessionID;
        obj->L1CryptoInit(L1Algorithms::Algorithms::HMACSHA256, 0,
            keyId, &sessionID);

        // SHA256 Update
        uint16_t chunkLen = dataInLen < L1Crypto::UpdateSize::DATAIN ? 
            dataInLen : L1Crypto::UpdateSize::DATAIN;
        while (dataInLen > 0)
        {
            obj->L1CryptoUpdate(sessionID, 0, chunkLen, dataIn, 0, NULL,
                NULL, NULL);
            
            dataIn += chunkLen;
            dataInLen -= chunkLen;
        }

        // FINIT
        obj->L1CryptoUpdate(sessionID, L1Crypto::UpdateFlags::FINIT, 0, NULL,
            0, NULL, dataOutLen, dataOut);
    }
    catch(...)
    {
        return -1;
    }

    return 0;
}
