#pragma once

#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>
#include <Tanker/Trustchain/Actions/UserGroupRemoval.hpp>
#include <Tanker/Trustchain/GroupAction.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <optional>

namespace Tanker
{
namespace Groups
{
class IRequester
{
public:
  virtual tc::cotask<std::vector<Trustchain::GroupAction>> getGroupBlocks(
      gsl::span<Trustchain::GroupId const> groupIds) = 0;

  virtual tc::cotask<std::vector<Trustchain::GroupAction>> getGroupBlocks(
      Crypto::PublicEncryptionKey const& groupEncryptionKey) = 0;

  virtual tc::cotask<void> createGroup(Trustchain::Actions::UserGroupCreation const& groupCreation) = 0;
  virtual tc::cotask<void> updateGroup(Trustchain::Actions::UserGroupAddition const& groupAddition) = 0;
  virtual tc::cotask<void> softUpdateGroup(
      Trustchain::Actions::UserGroupRemoval const& groupRemoval,
      std::optional<Trustchain::Actions::UserGroupAddition> const& groupAddition) = 0;

  virtual ~IRequester() = default;
};
}
}
