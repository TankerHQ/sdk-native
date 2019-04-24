#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Trustchain/ResourceId.hpp>

namespace Tanker
{
namespace EncryptionFormat
{
struct EncryptionMetadata
{
  Trustchain::ResourceId resourceId;
  Crypto::SymmetricKey key;
};
}
}
