#pragma once

#include <Tanker/Config/Config.hpp>

#include <fmt/core.h>

#include <stdexcept>
#include <string>
#include <utility>

namespace Tanker
{
namespace Error
{
enum class Code
{
  NoError,
  Other,
  InvalidTankerStatus,
  ServerError,
  InvalidArgument,
  ResourceKeyNotFound,
  UserNotFound,
  DecryptFailed,
  InvalidVerificationKey,
  InternalError,
  InvalidUnlockPassword,
  InvalidVerificationCode,
  VerificationKeyAlreadyExists,
  MaxVerificationAttemptsReached,
  InvalidGroupSize,
  RecipientNotFound,
  GroupNotFound,
  DeviceNotFound,
  IdentityAlreadyRegistered,
  OperationCanceled,
  NothingToClaim,

  Last,
};

class Exception : public std::exception
{
public:
  Exception(Code code, std::string message);

  char const* what() const noexcept override;

  Code code() const;
  std::string const& message() const;
  std::string const& backtrace() const;

protected:
  Code _code;
  std::string _message;
  std::string _backtrace;

  std::string _buffer;

  static std::string backtraceAsString();
};

template <typename EX = std::runtime_error, typename String, typename... Args>
TANKER_WARN_UNUSED_RESULT EX formatEx(String format, Args const&... args)
{
  return EX(fmt::format(format, args...));
}

#define DECLARE_ERROR(ErrCode)                       \
  class ErrCode : public Exception                   \
  {                                                  \
  public:                                            \
    ErrCode(std::string message)                     \
      : Exception(Code::ErrCode, std::move(message)) \
    {                                                \
    }                                                \
  }

DECLARE_ERROR(InvalidTankerStatus);
DECLARE_ERROR(InvalidArgument);
// ResourceKeyNotFound has its own header
// UserNotFound has its own header
DECLARE_ERROR(DecryptFailed);
DECLARE_ERROR(InvalidVerificationKey);
DECLARE_ERROR(InternalError);
DECLARE_ERROR(InvalidUnlockPassword);
DECLARE_ERROR(InvalidVerificationCode);
DECLARE_ERROR(VerificationKeyAlreadyExists);
DECLARE_ERROR(MaxVerificationAttemptsReached);
DECLARE_ERROR(InvalidGroupSize);
// RecipientNotFound has its own header
// GroupNotFound has its own header
DECLARE_ERROR(DeviceNotFound);
DECLARE_ERROR(IdentityAlreadyRegistered);
DECLARE_ERROR(OperationCanceled);
DECLARE_ERROR(NothingToClaim);

#undef DECLARE_ERROR

#define DECLARE_INTERNAL_ERROR(name)    \
  class name : public InternalError     \
  {                                     \
  public:                               \
    using InternalError::InternalError; \
  }

DECLARE_INTERNAL_ERROR(BlockNotFound);
DECLARE_INTERNAL_ERROR(UnexpectedBlock);
DECLARE_INTERNAL_ERROR(MigrationFailed);

#undef DECLARE_INTERNAL_ERROR

enum class VerificationCode
{
  InvalidSignature,
  InvalidAuthor,
  InvalidHash,
  InvalidUserKey,
  InvalidLastReset,
  InvalidUserId,
  InvalidDelegationSignature,
  InvalidUser,
  InvalidEncryptionKey,
  InvalidGroup,
  InvalidUserKeys,
  InvalidTargetDevice,
};

std::string to_string(VerificationCode n);

class VerificationFailed : public InternalError
{
public:
  VerificationFailed(VerificationCode code, std::string message);
  VerificationCode code() const;

private:
  VerificationCode _code;
};

#define DECLARE_ERROR_AS(err, code)                                      \
  class err : public Exception                                           \
  {                                                                      \
  public:                                                                \
    err(std::string message) : Exception(Code::code, std::move(message)) \
    {                                                                    \
    }                                                                    \
  }

DECLARE_ERROR_AS(UserKeyNotFound, ResourceKeyNotFound);
DECLARE_ERROR_AS(GroupKeyNotFound, ResourceKeyNotFound);
DECLARE_ERROR_AS(ProvisionalUserKeysNotFound, ResourceKeyNotFound);

#undef DECLARE_ERROR_AS

class ServerError : public Exception
{
public:
  ServerError(int httpStatus, std::string errorCode, std::string message);

  ServerError(std::string eventName,
              int httpStatus,
              std::string errorCode,
              std::string message);

  int httpStatusCode() const;

  std::string const& serverCode() const;
  std::string const& message() const;

private:
  std::string _errorCode;
  std::string _message;
  int _httpStatusCode;
};
}
}
