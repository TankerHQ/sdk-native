#pragma once

#include <Tanker/Crypto/SimpleResourceId.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>

namespace Tanker
{
struct EncryptionMetadata
{
  Crypto::SimpleResourceId resourceId;
  Crypto::SymmetricKey key;
};
}
