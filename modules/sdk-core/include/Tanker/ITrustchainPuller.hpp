#pragma once

#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <tconcurrent/future.hpp>

#include <vector>

namespace Tanker
{
class ITrustchainPuller
{
public:
  virtual tc::shared_future<void> scheduleCatchUp(
      std::vector<Trustchain::UserId> const& = {},
      std::vector<Trustchain::GroupId> const& = {}) = 0;
};
}