#pragma once

#include <vector>

#include <Tanker/Error.hpp>
#include <Tanker/GroupNotFound.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/UserNotFound.hpp>

namespace Tanker
{
namespace Error
{
class RecipientNotFoundInternal : public InternalError
{
public:
  RecipientNotFoundInternal() : InternalError("RecipientNotFoundInternal")
  {
  }

  RecipientNotFoundInternal(std::vector<Trustchain::UserId> userIds,
                            std::vector<GroupId> groupIds)
    : InternalError("RecipientNotFoundInternal"),
      _userIds(std::move(userIds)),
      _groupIds(std::move(groupIds))
  {
  }

  std::vector<Trustchain::UserId> const& userIds() const
  {
    return _userIds;
  }
  std::vector<GroupId> const& groupIds() const
  {
    return _groupIds;
  }

private:
  std::vector<Trustchain::UserId> _userIds;
  std::vector<GroupId> _groupIds;
};

class RecipientNotFound : public Exception,
                          public UserNotFoundBase,
                          public GroupNotFoundBase
{
public:
  RecipientNotFound(std::string message)
    : Exception(Code::RecipientNotFound, std::move(message)),
      UserNotFoundBase(),
      GroupNotFoundBase()
  {
  }

  RecipientNotFound(std::string message,
                    std::vector<SPublicIdentity> publicIdentities,
                    std::vector<GroupId> groupIds)
    : Exception(Code::RecipientNotFound, std::move(message)),
      UserNotFoundBase(std::move(publicIdentities)),
      GroupNotFoundBase(std::move(groupIds))
  {
  }
};
}
}
