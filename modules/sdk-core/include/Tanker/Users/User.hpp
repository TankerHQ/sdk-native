#pragma once

#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/Device.hpp>

#include <optional>
#include <vector>

namespace Tanker::Users
{
struct User
{
  Trustchain::UserId id;
  std::optional<Crypto::PublicEncryptionKey> userKey;
  std::vector<Device> devices;
};

bool operator==(User const& l, User const& r);
bool operator!=(User const& l, User const& r);
}
