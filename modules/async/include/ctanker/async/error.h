#ifndef TANKER_ERROR_C_H
#define TANKER_ERROR_C_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum tanker_error_code
{
  TANKER_ERROR_INVALID_ARGUMENT = 1,
  TANKER_ERROR_INTERNAL_ERROR = 2,
  TANKER_ERROR_NETWORK_ERROR = 3,
  TANKER_ERROR_PRECONDITION_FAILED = 4,
  TANKER_ERROR_OPERATION_CANCELED = 5,

  TANKER_ERROR_DECRYPTION_FAILED = 6,

  TANKER_ERROR_GROUP_TOO_BIG = 7,

  TANKER_ERROR_INVALID_VERIFICATION = 8,
  TANKER_ERROR_TOO_MANY_ATTEMPTS = 9,
  TANKER_ERROR_EXPIRED_VERIFICATION = 10,
  TANKER_ERROR_IO_ERROR = 11,
  TANKER_ERROR_DEVICE_REVOKED_LEGACY = 12, // unused but kept for following
                                           // error code compatibility

  TANKER_ERROR_CONFLICT = 13,
  TANKER_ERROR_UPGRADE_REQUIRED = 14,
  TANKER_ERROR_IDENTITY_ALREADY_ATTACHED = 15,

  TANKER_ERROR_LAST = 16,
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
