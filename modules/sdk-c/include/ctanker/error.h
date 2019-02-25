#ifndef CTANKER_SDK_TANKER_ERROR_H
#define CTANKER_SDK_TANKER_ERROR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum tanker_error_code
{
  TANKER_ERROR_NO_ERROR,
  TANKER_ERROR_OTHER,
  TANKER_ERROR_INVALID_TANKER_STATUS,
  TANKER_ERROR_SERVER_ERROR,
  TANKER_ERROR_INVALID_ARGUMENT,
  TANKER_ERROR_RESOURCE_KEY_NOT_FOUND,
  TANKER_ERROR_USER_NOT_FOUND,
  TANKER_ERROR_DECRYPT_FAILED,
  TANKER_ERROR_INVALID_UNLOCK_KEY,
  TANKER_ERROR_INTERNAL_ERROR,
  TANKER_ERROR_INVALID_UNLOCK_PASSWORD,
  TANKER_ERROR_INVALID_VERIFICATION_CODE,
  TANKER_ERROR_UNLOCK_KEY_ALREADY_EXISTS,
  TANKER_ERROR_MAX_VERIFICATION_ATTEMPTS_REACHED,
  TANKER_ERROR_INVALID_GROUP_SIZE,
  TANKER_ERROR_RECIPIENT_NOT_FOUND,
  TANKER_ERROR_GROUP_NOT_FOUND,
  TANKER_ERROR_DEVICE_NOT_FOUND,
  TANKER_ERROR_IDENTITY_ALREADY_REGISTERED,

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
