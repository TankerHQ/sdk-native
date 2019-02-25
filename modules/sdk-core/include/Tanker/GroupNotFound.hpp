#pragma once

#include <vector>

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Types/GroupId.hpp>

namespace Tanker
{
namespace Error
{
class GroupNotFoundBase
{
public:
  GroupNotFoundBase() = default;
  GroupNotFoundBase(std::vector<GroupId> const& groupIds) : _groupIds(groupIds)
  {
  }

  std::vector<GroupId> const& groupIds() const
  {
    return _groupIds;
  }

private:
  std::vector<GroupId> _groupIds;
};

class GroupNotFound : public Exception, public GroupNotFoundBase
{
public:
  GroupNotFound(std::string message)
    : Exception(Code::GroupNotFound, std::move(message))
  {
  }

  GroupNotFound(std::string message, std::vector<GroupId> const& groupIds)
    : Exception(Code::GroupNotFound, std::move(message)),
      GroupNotFoundBase(groupIds)
  {
  }
};
}
}
