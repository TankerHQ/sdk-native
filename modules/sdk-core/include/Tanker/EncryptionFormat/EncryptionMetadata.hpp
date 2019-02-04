#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Types/ResourceId.hpp>

namespace Tanker
{
namespace EncryptionFormat
{
struct EncryptionMetadata
{
  ResourceId resourceId;
  Crypto::SymmetricKey key;
};
}
}
