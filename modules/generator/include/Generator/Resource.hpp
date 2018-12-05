#pragma once

#include <Generator/Device.hpp>

#include <Generator/Utils.hpp>
#include <Tanker/BlockGenerator.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Types/DeviceId.hpp>

#include <vector>

namespace Tanker
{
namespace Generator
{
struct Resource
{
  Crypto::Mac mac = make_random_bytes<Crypto::Mac>();
  Crypto::SymmetricKey key = make_random_bytes<Crypto::SymmetricKey>();
};

struct Share
{
  Resource res;
  DeviceId sender;
  DeviceId recipient;
  Crypto::PrivateSignatureKey privateSigKey;
  std::vector<uint8_t> buffer;
  Crypto::Hash hash;

private:
  Share(Share const&) = delete;
  Share& operator=(Share const&) = delete;

public:
  Share(Share&&) = default;
  Share& operator=(Share&&) = default;

  Share(Device const& sender,
        Device const& recipient,
        Resource res = Resource{});
};
using Shares = std::vector<Share>;

} /* Generator */
} /* Tanker */
