#pragma once

#include <Tanker/Device.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <optional.hpp>

#include <vector>

namespace Tanker
{
struct User
{
  Trustchain::UserId id;
  nonstd::optional<Crypto::PublicEncryptionKey> userKey;
  std::vector<Device> devices;
};

bool operator==(User const& l, User const& r);
bool operator!=(User const& l, User const& r);
}
