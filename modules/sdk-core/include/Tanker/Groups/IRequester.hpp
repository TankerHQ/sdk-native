#pragma once

#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace Groups
{

class IRequester
{
public:
  virtual tc::cotask<std::vector<Trustchain::ServerEntry>> getGroupBlocks(
      std::vector<Trustchain::GroupId> const& groupIds) = 0;

  virtual tc::cotask<std::vector<Trustchain::ServerEntry>> getGroupBlocks(
      Crypto::PublicEncryptionKey const& groupEncryptionKey) = 0;
  virtual ~IRequester() = default;
};
}
}
