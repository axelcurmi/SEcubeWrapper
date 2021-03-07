#ifndef _L0_WRAPPER_H
#define _L0_WRAPPER_H

#include <stdint.h>

extern "C" {
    struct L0_handler;
    typedef struct L0_handler L0_handler_t;

    L0_handler_t *L0_create();
    void L0_destroy(L0_handler_t *l0);

    uint8_t L0_getNumberDevices(L0_handler_t *l0);
}

#endif // !_L0_WRAPPER_H
