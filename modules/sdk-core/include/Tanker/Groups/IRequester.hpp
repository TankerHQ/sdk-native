#pragma once

#include <Tanker/Trustchain/Actions/UserGroupCreation.hpp>
#include <Tanker/Trustchain/GroupAction.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <gsl/gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Groups
{
class IRequester
{
public:
  enum class IsLight
  {
    No,
    Yes,
  };

  virtual tc::cotask<std::vector<Trustchain::GroupAction>> getGroupBlocks(
      gsl::span<Trustchain::GroupId const> groupIds, IsLight isLight) = 0;

  virtual tc::cotask<std::vector<Trustchain::GroupAction>> getGroupBlocks(
      Crypto::PublicEncryptionKey const& groupEncryptionKey) = 0;

  virtual tc::cotask<void> createGroup(
      Trustchain::Actions::UserGroupCreation const& groupCreation) = 0;
  virtual tc::cotask<void> updateGroup(
      Trustchain::Actions::UserGroupAddition const& groupAddition) = 0;
  virtual tc::cotask<void> updateGroup(
      Trustchain::Actions::UserGroupUpdate const& groupUpdate) = 0;

  virtual ~IRequester() = default;
};
}
}
