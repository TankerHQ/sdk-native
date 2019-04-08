#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Serialization/Serialization.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstddef>

namespace Tanker
{
struct UserKeyPair
{
  Crypto::PublicEncryptionKey publicEncryptionKey;
  Crypto::SealedPrivateEncryptionKey encryptedPrivateEncryptionKey;
};

bool operator==(UserKeyPair const& l, UserKeyPair const& r);
bool operator!=(UserKeyPair const& l, UserKeyPair const& r);

constexpr std::size_t serialized_size(UserKeyPair const& uk)
{
  return uk.publicEncryptionKey.arraySize +
         uk.encryptedPrivateEncryptionKey.arraySize;
}

std::uint8_t* to_serialized(std::uint8_t* it, UserKeyPair const& ukp);

void from_serialized(Serialization::SerializedSource& ss, UserKeyPair&);

void to_json(nlohmann::json& j, UserKeyPair const& ukp);
}
