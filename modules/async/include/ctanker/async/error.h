#ifndef TANKER_ERROR_C_H
#define TANKER_ERROR_C_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum tanker_error_code
{
  TANKER_ERROR_INVALID_ARGUMENT = 1,
  TANKER_ERROR_INTERNAL_ERROR,
  TANKER_ERROR_NETWORK_ERROR,
  TANKER_ERROR_PRECONDITION_FAILED,
  TANKER_ERROR_OPERATION_CANCELED,

  TANKER_ERROR_DECRYPTION_FAILED,

  TANKER_ERROR_GROUP_TOO_BIG,

  TANKER_ERROR_INVALID_VERIFICATION,
  TANKER_ERROR_TOO_MANY_ATTEMPTS,
  TANKER_ERROR_EXPIRED_VERIFICATION,
  TANKER_ERROR_IO_ERROR,
  TANKER_ERROR_DEVICE_REVOKED,

  TANKER_ERROR_CONFLICT,
  TANKER_ERROR_UPGRADE_REQUIRED,

  TANKER_ERROR_LAST,
};

typedef uint32_t tanker_error_code_t;

struct tanker_error
{
  tanker_error_code_t code;
  char const* message;
};

#ifdef __cplusplus
}
#endif

#endif
