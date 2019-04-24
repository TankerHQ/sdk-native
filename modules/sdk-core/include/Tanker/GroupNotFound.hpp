#pragma once

#include <vector>

#include <Tanker/Error.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

namespace Tanker
{
namespace Error
{
class GroupNotFoundBase
{
public:
  GroupNotFoundBase() = default;
  GroupNotFoundBase(std::vector<Trustchain::GroupId> const& groupIds)
    : _groupIds(groupIds)
  {
  }

  std::vector<Trustchain::GroupId> const& groupIds() const
  {
    return _groupIds;
  }

private:
  std::vector<Trustchain::GroupId> _groupIds;
};

class GroupNotFound : public Exception, public GroupNotFoundBase
{
public:
  GroupNotFound(std::string message)
    : Exception(Code::GroupNotFound, std::move(message))
  {
  }

  GroupNotFound(std::string message,
                std::vector<Trustchain::GroupId> const& groupIds)
    : Exception(Code::GroupNotFound, std::move(message)),
      GroupNotFoundBase(groupIds)
  {
  }
};
}
}
