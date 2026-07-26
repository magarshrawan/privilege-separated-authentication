#ifndef AUTH_PROTOCOL_H
#define AUTH_PROTOCOL_H

#include <stdint.h>

#define AUTH_MAGIC 0x41555448u
#define AUTH_VERSION 1u
#define AUTH_OP_VALIDATE 1u
#define AUTH_MAX_USER 64u
#define AUTH_MAX_PASSWORD 256u

struct auth_request {
    uint32_t magic;
    uint16_t version;
    uint16_t operation;
    uint32_t username_length;
    uint32_t password_length;
    char username[AUTH_MAX_USER];
};

struct auth_response {
    uint32_t magic;
    uint16_t version;
    uint16_t authenticated;
};

#endif
