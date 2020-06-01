#pragma once

#include <Tanker/Trustchain/ClientEntry.hpp>
#include <Tanker/Trustchain/GroupAction.hpp>

#include <tconcurrent/coroutine.hpp>

#include <gsl-lite.hpp>

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

  tc::cotask<void> pushBlock(Trustchain::GroupAction const& action);
  tc::cotask<void> pushBlock(Trustchain::ClientEntry const& entry);
  tc::cotask<void> pushKeys(gsl::span<Trustchain::ClientEntry const> entries);

private:
  Client* _client;
};
}
