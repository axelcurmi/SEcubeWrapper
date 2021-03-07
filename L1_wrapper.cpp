#include "SEcubeSources/L1/L1.h"
#include "L1_wrapper.h"

#include <stdio.h>

struct L1_handler
{
	void *obj;
};

L1_handler_t *L1_create()
{
	L1_handler_t *l1;
	L1 *obj;

	l1 = (L1_handler_t *)malloc(sizeof(L1_handler));
	obj = new L1();

	l1->obj = obj;
	return l1;
}

void L1_destroy(L1_handler_t *l1)
{
	delete (L1 *)l1->obj;
	free(l1);
}

int8_t L1_Login(L1_handler_t *l1, const uint8_t *pin, uint16_t access,
				bool force)
{
	L1 *obj = (L1 *)l1->obj;
	try
	{
		obj->L1Login(pin, access, force);
	}
	catch (L1LoginException)
	{
		return -1;
	}
	return 0;
}

int8_t L1_Logout(L1_handler_t *l1)
{
	L1 *obj = (L1 *)l1->obj;
	try
	{
		obj->L1Logout();
	}
	catch (L1Exception)
	{
		return -1;
	}
	return 0;
}
