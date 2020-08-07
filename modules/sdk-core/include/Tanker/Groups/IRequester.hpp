#pragma once

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
  virtual tc::cotask<std::vector<Trustchain::GroupAction>> getGroupBlocks(
      gsl::span<Trustchain::GroupId const> groupIds) = 0;

  virtual tc::cotask<std::vector<Trustchain::GroupAction>> getGroupBlocks(
      Crypto::PublicEncryptionKey const& groupEncryptionKey) = 0;
  virtual ~IRequester() = default;
};
}
}
