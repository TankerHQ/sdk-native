#pragma once

#include <Tanker/EnumTrait.hpp>

#include <fmt/format.h>

#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

#ifdef __GNUC__
#define TANKER_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#else
#define TANKER_WARN_UNUSED_RESULT
#endif

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
  Unused1,
  InvalidArgument,
  ResourceKeyNotFound,
  UserNotFound,
  DecryptFailed,
  InvalidUnlockEventHandler,
  ChunkIndexOutOfRange,
  VersionNotSupported,
  InvalidUnlockKey,
  InternalError,
  ChunkNotFound,
  InvalidUnlockPassword,
  InvalidVerificationCode,
  UnlockKeyAlreadyExists,
  MaxVerificationAttemptsReached,
  InvalidGroupSize,
  RecipientNotFound,
  GroupNotFound,
  DeviceNotFound,

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
DECLARE_ERROR(ResourceKeyNotFound);
// UserNotFound has its own header
DECLARE_ERROR(DecryptFailed);
DECLARE_ERROR(InvalidUnlockEventHandler);
DECLARE_ERROR(ChunkIndexOutOfRange);
DECLARE_ERROR(VersionNotSupported);
DECLARE_ERROR(InvalidUnlockKey);
DECLARE_ERROR(InternalError);
DECLARE_ERROR(ChunkNotFound);
DECLARE_ERROR(InvalidUnlockPassword);
DECLARE_ERROR(InvalidVerificationCode);
DECLARE_ERROR(UnlockKeyAlreadyExists);
DECLARE_ERROR(MaxVerificationAttemptsReached);
DECLARE_ERROR(InvalidGroupSize);
// RecipientNotFound has its own header
// GroupNotFound has its own header
DECLARE_ERROR(DeviceNotFound);

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

// Let's expose this error as ResourceKeyNotFound to the user
class UserKeyNotFound : public ResourceKeyNotFound
{
public:
  using ResourceKeyNotFound::ResourceKeyNotFound;
};

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

template <>
struct is_enum_type<Error::VerificationCode> : std::true_type
{
};
}
