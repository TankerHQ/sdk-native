#pragma once

#include <vector>

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Types/UserId.hpp>

namespace Tanker
{
namespace Error
{

class UserNotFoundBase
{
public:
  UserNotFoundBase() = default;
  UserNotFoundBase(std::vector<UserId> const& userIds)
    : _userIds(userIds)
  {
  }

  std::vector<UserId> const& userIds() const
  {
    return _userIds;
  }

private:
  std::vector<UserId> _userIds;
};

class UserNotFound : public Exception, public UserNotFoundBase
{
public:
  UserNotFound(std::string message)
    : Exception(Code::UserNotFound, std::move(message))
  {
  }

  UserNotFound(std::string message, std::vector<UserId> const& userIds)
    : Exception(Code::UserNotFound, std::move(message)), UserNotFoundBase(userIds)
  {
  }
};
}
}
