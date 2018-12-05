#pragma once

#include <vector>

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/UserNotFound.hpp>
#include <Tanker/GroupNotFound.hpp>

namespace Tanker
{
namespace Error
{
class RecipientNotFound : public Exception, public UserNotFoundBase, public GroupNotFoundBase
{
public:
  RecipientNotFound(std::string message)
    : Exception(Code::RecipientNotFound, std::move(message)),
    UserNotFoundBase(),
    GroupNotFoundBase()
  {
  }

  RecipientNotFound(std::string message,
                    std::vector<UserId> userIds,
                    std::vector<GroupId> groupIds)
    : Exception(Code::RecipientNotFound, std::move(message)),
    UserNotFoundBase(std::move(userIds)),
    GroupNotFoundBase(std::move(groupIds))
  {
  }
};
}
}
