#pragma once

#include <vector>

#include <Tanker/Error.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/SPublicIdentity.hpp>

namespace Tanker
{
namespace Error
{

class UserNotFoundInternal
{
public:
  UserNotFoundInternal() = default;
  UserNotFoundInternal(std::vector<Trustchain::UserId> userIds)
    : _userIds(std::move(userIds))
  {
  }

  std::vector<Trustchain::UserId> const& userIds() const
  {
    return _userIds;
  }

private:
  std::vector<Trustchain::UserId> _userIds;
};

class UserNotFoundBase
{
public:
  UserNotFoundBase() = default;
  UserNotFoundBase(std::vector<SPublicIdentity> publicIdentities)
    : _publicIdentities(std::move(publicIdentities))
  {
  }
  UserNotFoundBase(SPublicIdentity publicIdentity)
    : _publicIdentities({std::move(publicIdentity)})
  {
  }

  std::vector<SPublicIdentity> const& publicIdentities() const
  {
    return _publicIdentities;
  }

private:
  std::vector<SPublicIdentity> _publicIdentities;
};

class UserNotFound : public Exception, public UserNotFoundBase
{
public:
  UserNotFound(std::string message)
    : Exception(Code::UserNotFound, std::move(message))
  {
  }

  UserNotFound(std::string message,
               std::vector<SPublicIdentity> publicIdentities = {})
    : Exception(Code::UserNotFound, std::move(message)),
      UserNotFoundBase(std::move(publicIdentities))
  {
  }

  UserNotFound(std::string message, SPublicIdentity publicIdentity)
    : Exception(Code::UserNotFound, std::move(message)),
      UserNotFoundBase(std::move(publicIdentity))
  {
  }
};
}
}
