#pragma once

#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>
#include <Tanker/Trustchain/GroupAction.hpp>
#include <Tanker/Trustchain/KeyPublishAction.hpp>
#include <Tanker/Trustchain/UserAction.hpp>

#include <tconcurrent/coroutine.hpp>

#include <gsl/gsl-lite.hpp>

#include <cstdint>
#include <vector>

namespace Tanker
{
class Client;

class Pusher
{
public:
  Pusher(Client* client);

  Pusher(Pusher const&) = delete;
  Pusher& operator=(Pusher const&) = delete;
  Pusher(Pusher&&) = delete;
  Pusher& operator=(Pusher&&) = delete;

  tc::cotask<void> pushBlock(Trustchain::UserAction const& action);
  tc::cotask<void> pushBlock(Trustchain::GroupAction const& action);
  tc::cotask<void> pushBlock(
      Trustchain::Actions::ProvisionalIdentityClaim const& action);
  tc::cotask<void> pushKeys(
      gsl::span<Trustchain::KeyPublishAction const> entries);

private:
  Client* _client;
};
}
