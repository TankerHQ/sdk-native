#pragma once

#include <Tanker/Trustchain/ClientEntry.hpp>

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

  tc::cotask<void> pushBlock(Trustchain::ClientEntry const& entry);
  tc::cotask<void> pushKeys(gsl::span<Trustchain::ClientEntry const> entries);

private:
  Client* _client;
};
}
