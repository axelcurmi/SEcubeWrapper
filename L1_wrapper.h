#ifndef _L1_WRAPPER_H
#define _L1_WRAPPER_H

#include <stdint.h>

extern "C"
{
    struct L1_handler;
    typedef struct L1_handler L1_handler_t;

    L1_handler_t *L1_create();
    void L1_destroy(L1_handler_t *l1);

    int8_t L1_Login(L1_handler_t *l1, const uint8_t *pin, uint16_t access,
                    bool force);
    int8_t L1_Logout(L1_handler_t *l1);
}

#endif // !_L1_WRAPPER_H
