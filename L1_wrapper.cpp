#include "SEcubeSources/L1/L1.h"
#include "L1_wrapper.h"

#include <stdio.h>

struct L1_handle
{
	void *obj;
};

L1_handle_t *L1_Create()
{
	L1_handle_t *l1;
	L1 *obj;

	l1 = (L1_handle_t *)malloc(sizeof(L1_handle));
	obj = new L1();

	l1->obj = obj;
	return l1;
}

void L1_Destroy(L1_handle_t *l1)
{
	delete (L1 *)l1->obj;
	free(l1);
}

int8_t L1_Login(L1_handle_t *l1, const uint8_t *pin, uint16_t access,
				bool force)
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

int8_t L1_KeyEdit(L1_handle_t *l1, se3Key* key, uint16_t op)
{
	L1 *obj = (L1 *)l1->obj;
	try
	{
		obj->L1KeyEdit(key, op);
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

int8_t L1_Encrypt(L1_handle_t *l1, size_t dataInLen, uint8_t* dataIn,
				  size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm,
				  uint16_t mode, uint32_t keyID)
{
	L1 *obj = (L1 *)l1->obj;
	try
	{
		obj->L1Encrypt(dataInLen, dataIn, dataOutLen, dataOut, algorithm,
					   mode, keyID);
	}
	catch (...)
	{
		return -1;
	}
	return 0;
}

int8_t L1_Decrypt(L1_handle_t *l1, size_t dataInLen, uint8_t* dataIn,
				 size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm,
				 uint16_t mode, uint32_t keyID)
{
	L1 *obj = (L1 *)l1->obj;
	try
	{
		obj->L1Decrypt(dataInLen, dataIn, dataOutLen, dataOut, algorithm,
					   mode, keyID);
	}
	catch (...)
	{
		return -1;
	}
	return 0;
}

/**
 * 
 * The L1Digest function provided by the SEcube L1 host library seems broken
 * with an infinite loop and since the session is closed after the first
 * iteration, the second iteration throws an exception as it attempts to use
 * the closed session.
 * 
 * This function has two problems being:
 *   1) The L1CryptoInit function has to be supplied with a key id. This is
 * 		because if you attempt to execute the L1CryptoInit function with a "0"
 * 		(zero) as the keyId and no key with Id "0" exists, an exception is
 		thrown (I assume this is a bug).
 *   2) This function will not handle very large data
 * 		(> L1Crypto::UpdateSize::DATAIN), like L1Encrypt and
 * 		L1Decrypt, as it does not have the looping mechanism.
 * 
 */
int8_t L1_Digest(L1_handle_t *l1, size_t dataInLen, uint8_t* dataIn,
                    size_t* dataOutLen, uint8_t* dataOut, uint16_t algorithm)
{
	L1 *obj = (L1 *)l1->obj;
	try
	{
		uint32_t sessionId;

		obj->L1CryptoInit(algorithm, 0, 0, &sessionId);
		obj->L1CryptoUpdate(sessionId, L1Crypto::UpdateFlags::FINIT,
			dataInLen, dataIn, 0, NULL, (uint16_t *)dataOutLen, dataOut);
	}
	catch(...)
	{
		return -1;
	}

	return 0;
}

int8_t L1_CryptoInit(L1_handle_t *l1, uint16_t algorithm, uint16_t mode,
					 uint32_t keyID, uint32_t* sessionID)
{
	L1 *obj = (L1 *)l1->obj;

	try
	{
		obj->L1CryptoInit(algorithm, mode, keyID, sessionID);
	}
	catch (...)
	{
		return -1;
	}

	return 0;
}

int8_t L1_CryptoUpdate(L1_handle_t *l1, uint32_t sessionID, uint16_t flags,
                           uint16_t dataInLen, uint8_t* dataIn,
                           uint16_t* dataOutLen, uint8_t* dataOut)
{
	L1 *obj = (L1 *)l1->obj;

	try
	{
		obj->L1CryptoUpdate(sessionID, flags, 0, NULL, dataInLen, dataIn,
							dataOutLen, dataOut);
	}
	catch (...)
	{
		return -1;
	}

	return 0;
}
