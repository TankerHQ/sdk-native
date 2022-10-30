#pragma once

#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>

namespace Tanker
{
/// The key to save in cache with its corresponding simple resource ID
/// Not necessarily the full ciphertext's resource ID, which can be a composite
struct EncryptCacheMetadata
{
  Crypto::SimpleResourceId resourceId;
  Crypto::SymmetricKey key;
};
}
