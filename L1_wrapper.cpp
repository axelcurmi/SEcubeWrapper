#include "SEcubeSources/L1/L1.h"
#include "L1_wrapper.h"

#include <stdio.h>
#include <time.h>

#ifdef L1_METRICS
struct L1_metrics
{
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
#ifdef L1_METRICS
    printf("SEcube:INFO:CryptoInitCount: %d\n", l1->metrics->CryptoInitCount);
    printf("SEcube:INFO:CryptoInitTime: %f\n", l1->metrics->CryptoInitTime);
    printf("SEcube:INFO:CryptoUpdateCount: %d\n", l1->metrics->CryptoUpdateCount);
    printf("SEcube:INFO:CryptoUpdateTime: %f\n", l1->metrics->CryptoUpdateTime);
#endif // L1_METRICS
#endif // INFO_LOG

    delete (L1 *)l1->obj;
    free(l1);
}

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
    return obj->L1FindKey(keyID);
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
                start = clock();
#endif // L1_METRICS
                obj->L1CryptoUpdate(sessionId, flags, chunkLen, data1, 0, NULL,
                    &chunkOutLen, dataOut);
#ifdef L1_METRICS
            end = clock();
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
                start = clock();
#endif // L1_METRICS
                obj->L1CryptoUpdate(sessionId, flags, data1Len, data1, chunkLen,
                    data2, &chunkOutLen, dataOut);
#ifdef L1_METRICS
                end = clock();
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
            obj->L1CryptoUpdate(sessionID, 0, chunkLen, dataIn, 0, NULL,
                NULL, NULL);
            
            dataIn += chunkLen;
            dataInLen -= chunkLen;
        }

        // FINIT
#ifdef L1_METRICS
            l1->metrics->CryptoUpdateCount += 1;
            clock_t start = clock();
#endif // L1_METRICS
        obj->L1CryptoUpdate(sessionID, L1Crypto::UpdateFlags::FINIT, 0, NULL,
            0, NULL, dataOutLen, dataOut);
#ifdef L1_METRICS
            clock_t end = clock();
            l1->metrics->CryptoUpdateTime += ((double) end - start) / CLOCKS_PER_SEC;
#endif // L1_METRICS
    }
    catch(...)
    {
        return -1;
    }
    
    return 0;
}
