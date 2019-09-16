#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

namespace Tanker
{
struct EncryptionMetadata
{
  Trustchain::ResourceId resourceId;
  Crypto::SymmetricKey key;
};
}
