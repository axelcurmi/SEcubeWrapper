#include "SEcubeSources/L1/L1.h"
#include "L1_wrapper.h"

#include <stdio.h>
#include <time.h>

#ifdef L1_METRICS
struct L1_metrics
{
    int FindKeyCount;
    double FindKeyTime;

    int EditKeyCount;
    double EditKeyTime;

    int CryptoInitCount;
    double CryptoInitTime;

    int CryptoUpdateCount;
    double CryptoUpdateTime;
};
#endif // L1_METRICS

struct L1_handle
{
#ifdef L1_METRICS
    L1_metrics_t *metrics;
#endif // L1_METRICS
    void *obj;
};

L1_handle_t *L1_Create()
{
#ifdef INFO_LOG
    printf("SEcube:INFO:Creating L1\n");
#endif // INFO_LOG

    L1_handle_t *l1;
    L1 *obj;

    l1 = (L1_handle_t *)malloc(sizeof(L1_handle));

    obj = new L1();
    l1->obj = obj;

#ifdef L1_METRICS
    L1_metrics_t *l1_metrics;
    l1_metrics = (L1_metrics_t *)malloc(sizeof(L1_metrics));
    memset(l1_metrics, 0, sizeof(L1_metrics));
    l1->metrics = l1_metrics;
#endif // L1_METRICS

    return l1;
}

void L1_Destroy(L1_handle_t *l1)
{
#ifdef INFO_LOG
    printf("SEcube:INFO:Destroying L1\n");
#endif // INFO_LOG

    delete (L1 *)l1->obj;
    free(l1);
}

#ifdef L1_METRICS
// TODO [AC]: A structure would be better.
// But I need to learn to use structures using Python "ctypes" first.
void L1_GetMetrics(L1_handle_t *l1, uint32_t *findKeyCount, double *findKeyTime,
    uint32_t *editKeyCount, double *editKeyTime,
    uint32_t *cryptoInitCount, double *cryptoInitTime,
    uint32_t *cryptoUpdateCount, double *cryptoUpdateTime)
{
    if (findKeyCount != NULL) {
        *findKeyCount = l1->metrics->FindKeyCount;
    }

    if (findKeyTime != NULL) {
        *findKeyTime = l1->metrics->FindKeyTime;
    }

    if (editKeyCount != NULL) {
        *editKeyCount = l1->metrics->EditKeyCount;
    }

    if (editKeyTime != NULL) {
        *editKeyTime = l1->metrics->EditKeyTime;
    }

    if (cryptoInitCount != NULL) {
        *cryptoInitCount = l1->metrics->CryptoInitCount;
    }

    if (cryptoInitTime != NULL) {
        *cryptoInitTime = l1->metrics->CryptoInitTime;
    }

    if (cryptoUpdateCount != NULL) {
        *cryptoUpdateCount = l1->metrics->CryptoUpdateCount;
    }

    if (cryptoUpdateTime != NULL) {
        *cryptoUpdateTime = l1->metrics->CryptoUpdateTime;
    }
}
#endif // L1_METRICS

int8_t L1_Login(L1_handle_t *l1, const uint8_t *pin, uint16_t access,
    uint8_t force)
{
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
    L1 *obj = (L1 *)l1->obj;
#ifdef L1_METRICS
    l1->metrics->FindKeyCount += 1;
    clock_t start = clock();
#endif // L1_METRICS
    int8_t result = obj->L1FindKey(keyID);
#ifdef L1_METRICS
    clock_t end = clock();
    l1->metrics->FindKeyTime += ((double) end - start) / CLOCKS_PER_SEC;
#endif // L1_METRICS

    return result;
}

int8_t L1_KeyEdit(L1_handle_t *l1, uint32_t id, uint32_t validity,
    uint16_t dataSize, uint16_t nameSize, uint8_t* data, uint8_t* name,
    uint16_t op)
{
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
#ifdef L1_METRICS
        l1->metrics->EditKeyCount += 1;
        clock_t start = clock();
#endif // L1_METRICS
        obj->L1KeyEdit(&key, op);
#ifdef L1_METRICS
        clock_t end = clock();
        l1->metrics->EditKeyTime += ((double) end - start) / CLOCKS_PER_SEC;
#endif // L1_METRICS
    }
    catch (...)
    {
        return -1;
    }
    return 0;
}

int8_t L1_CryptoSetTimeNow(L1_handle_t *l1)
{
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
    L1 *obj = (L1 *)l1->obj;
    try
    {
#ifdef L1_METRICS
        l1->metrics->CryptoInitCount += 1;
        clock_t start = clock();
#endif // L1_METRICS
        obj->L1CryptoInit(algorithm, flags, keyId, sessionId);
#ifdef L1_METRICS
        clock_t end = clock();
        l1->metrics->CryptoInitTime += ((double) end - start) / CLOCKS_PER_SEC;
#endif // L1_METRICS
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
    L1 *obj = (L1 *)l1->obj;
    try
    {
        if (dataOutLen != NULL)
        {
            *dataOutLen = 0;
        }

        if (data1Len == 0 and data2Len == 0)
        {
#ifdef L1_METRICS
            l1->metrics->CryptoUpdateCount += 1;
            clock_t start = clock();
#endif // L1_METRICS
            obj->L1CryptoUpdate(sessionId, flags, 0, NULL, 0, NULL,
                    dataOutLen, dataOut);
#ifdef L1_METRICS
            clock_t end = clock();
            l1->metrics->CryptoUpdateTime += ((double) end - start) / CLOCKS_PER_SEC;
#endif // L1_METRICS
        }
        else if (data2Len == 0)
        {
            while (data1Len > 0)
            {
                uint16_t chunkLen = data1Len < L1Crypto::UpdateSize::DATAIN ? 
                    data1Len : L1Crypto::UpdateSize::DATAIN;
                uint16_t chunkOutLen = 0;

#ifdef L1_METRICS
                l1->metrics->CryptoUpdateCount += 1;
                clock_t start = clock();
#endif // L1_METRICS
                obj->L1CryptoUpdate(sessionId, flags, chunkLen, data1, 0, NULL,
                    &chunkOutLen, dataOut);
#ifdef L1_METRICS
                clock_t end = clock();
            l1->metrics->CryptoUpdateTime += ((double) end - start) / CLOCKS_PER_SEC;
#endif // L1_METRICS

                data1 += chunkLen;
                data1Len -= chunkLen;

                if (dataOut != NULL) {
                    dataOut += chunkLen;
                }

                if (dataOutLen != NULL) {
                    *dataOutLen += chunkOutLen;
                }
            }
        }
        else
        {
            while (data2Len > 0)
            {
                uint16_t chunkLen = data2Len < L1Crypto::UpdateSize::DATAIN ? 
                    data2Len : L1Crypto::UpdateSize::DATAIN;
                uint16_t chunkOutLen = 0;
#ifdef L1_METRICS
                l1->metrics->CryptoUpdateCount += 1;
                clock_t start = clock();
#endif // L1_METRICS
                obj->L1CryptoUpdate(sessionId, flags, data1Len, data1, chunkLen,
                    data2, &chunkOutLen, dataOut);
#ifdef L1_METRICS
                clock_t end = clock();
                l1->metrics->CryptoUpdateTime += ((double) end - start) / CLOCKS_PER_SEC;
#endif // L1_METRICS

                data2 += chunkLen;
                dataOut += chunkLen;
                data2Len -= chunkLen;
                *dataOutLen += chunkOutLen;
            }
        }
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
    L1 *obj = (L1 *)l1->obj;
    try
    {
        // Create session
        uint32_t sessionID;

#ifdef L1_METRICS
        l1->metrics->CryptoInitCount += 1;
        clock_t start = clock();
#endif // L1_METRICS
        obj->L1CryptoInit(L1Algorithms::Algorithms::SHA256, 0, SHA256_KEY_ID,
            &sessionID);
#ifdef L1_METRICS
        clock_t end = clock();
        l1->metrics->CryptoInitTime += ((double) end - start) / CLOCKS_PER_SEC;
#endif // L1_METRICS

        // SHA256 Update
        while (dataInLen > 0)
        {
            uint16_t chunkLen = dataInLen < L1Crypto::UpdateSize::DATAIN ? 
                dataInLen : L1Crypto::UpdateSize::DATAIN;
#ifdef L1_METRICS
            l1->metrics->CryptoUpdateCount += 1;
            start = clock();
#endif // L1_METRICS
            obj->L1CryptoUpdate(sessionID, 0, chunkLen, dataIn, 0, NULL,
                NULL, NULL);
#ifdef L1_METRICS
            end = clock();
            l1->metrics->CryptoUpdateTime += ((double) end - start) / CLOCKS_PER_SEC;
#endif // L1_METRICS
            
            dataIn += chunkLen;
            dataInLen -= chunkLen;
        }

        // FINIT
#ifdef L1_METRICS
            l1->metrics->CryptoUpdateCount += 1;
            start = clock();
#endif // L1_METRICS
        obj->L1CryptoUpdate(sessionID, L1Crypto::UpdateFlags::FINIT, 0, NULL,
            0, NULL, dataOutLen, dataOut);
#ifdef L1_METRICS
            end = clock();
            l1->metrics->CryptoUpdateTime += ((double) end - start) / CLOCKS_PER_SEC;
#endif // L1_METRICS
    }
    catch(...)
    {
        return -1;
    }
    
    return 0;
}
