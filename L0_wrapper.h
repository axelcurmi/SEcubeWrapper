#ifndef _L0_WRAPPER_H
#define _L0_WRAPPER_H

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct L0_handler;
typedef struct L0_handler L0_handler_t;

L0_handler_t *L0_Create();
void L0_Destroy(L0_handler_t *l0);

uint8_t L0_GetNumberDevices(L0_handler_t *l0);

#ifdef __cplusplus
}
#endif

#endif // !_L0_WRAPPER_H
