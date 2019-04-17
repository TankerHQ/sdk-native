#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/PublicEncryptionKey.hpp>
#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Serialization/SerializedSource.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <cstddef>
#include <cstdint>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
// The nature is not present in the wired payload.
// Therefore there is no from_serialized overload for DeviceCreation.
// from_serialized(Action&) will construct abstract actions.
std::uint8_t* to_serialized(std::uint8_t*, DeviceCreation const&);

std::size_t serialized_size(DeviceCreation const&);
}
}
}
