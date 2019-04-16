#pragma once

#include <vector>

#include <Tanker/Error.hpp>
#include <Tanker/Trustchain/UserId.hpp>

namespace Tanker
{
namespace Error
{

class UserNotFoundBase
{
public:
  UserNotFoundBase() = default;
  UserNotFoundBase(std::vector<Trustchain::UserId> const& userIds)
    : _userIds(userIds)
  {
  }
  UserNotFoundBase(Trustchain::UserId const& userId)
  {
    _userIds.push_back(userId);
  }

  std::vector<Trustchain::UserId> const& userIds() const
  {
    return _userIds;
  }

private:
  std::vector<Trustchain::UserId> _userIds;
};

class UserNotFound : public Exception, public UserNotFoundBase
{
public:
  UserNotFound(std::string message)
    : Exception(Code::UserNotFound, std::move(message))
  {
  }

  UserNotFound(std::string message,
               std::vector<Trustchain::UserId> const& userIds)
    : Exception(Code::UserNotFound, std::move(message)),
      UserNotFoundBase(userIds)
  {
  }

  UserNotFound(std::string message, Trustchain::UserId const& userId)
    : Exception(Code::UserNotFound, std::move(message)),
      UserNotFoundBase(userId)
  {
  }
};
}
}
