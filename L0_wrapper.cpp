#include "SEcubeSources/L0/L0.h"
#include "L0_wrapper.h"

struct L0_handler {
	void *obj;
};

L0_handler_t *L0_create()
{
	L0_handler_t *l0;
	L0 *obj;

    l0 = (L0_handler_t *)malloc(sizeof(L0_handler));
    obj = new L0();

    l0->obj = obj;
    return l0;
}

void L0_destroy(L0_handler_t *l0)
{
	delete (L0 *) l0->obj;
	free(l0);
}

uint8_t L0_getNumberDevices(L0_handler_t *l0)
{
    return ((L0 *)l0->obj)->GetNumberDevices();
}
