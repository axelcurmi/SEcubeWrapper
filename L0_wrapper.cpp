#include "SEcubeSources/L0/L0.h"
#include "L0_wrapper.h"

struct L0_handler {
	void *obj;
};

L0_handler_t *L0_Create()
{
#ifdef DEBUG_LOG
    printf("[DEBUG_LOG] L0_Create\n");
#endif // DEBUG_LOG

#ifdef INFO_LOG
    printf("SEcube:INFO:Creating L0\n");
#endif // INFO_LOG

	L0_handler_t *l0;
	L0 *obj;

    l0 = (L0_handler_t *)malloc(sizeof(L0_handler));
    obj = new L0();

    l0->obj = obj;
    return l0;
}

void L0_Destroy(L0_handler_t *l0)
{
#ifdef DEBUG_LOG
    printf("[DEBUG_LOG] L0_Destroy\n");
#endif // DEBUG_LOG

#ifdef INFO_LOG
    printf("SEcube:INFO:Destroying L0\n");
#endif // INFO_LOG

	delete (L0 *) l0->obj;
	free(l0);
}

uint8_t L0_GetNumberDevices(L0_handler_t *l0)
{
#ifdef DEBUG_LOG
    printf("[DEBUG_LOG] L0_GetNumberDevices\n");
#endif // DEBUG_LOG

    return ((L0 *)l0->obj)->GetNumberDevices();
}
