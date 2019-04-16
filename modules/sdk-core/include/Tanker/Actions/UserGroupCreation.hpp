#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Groups/GroupEncryptedKey.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>
#include <optional.hpp>

#include <cstddef>
#include <vector>

namespace Tanker
{
struct UserGroupCreation
{
  using GroupEncryptedKeys = std::vector<GroupEncryptedKey>;

  Crypto::PublicSignatureKey publicSignatureKey;
  Crypto::PublicEncryptionKey publicEncryptionKey;
  Crypto::SealedPrivateSignatureKey encryptedPrivateSignatureKey;
  GroupEncryptedKeys encryptedGroupPrivateEncryptionKeysForUsers;
  Crypto::Signature selfSignature;

  Trustchain::Actions::Nature nature() const;
  std::vector<Index> makeIndexes() const;
  std::vector<uint8_t> signatureData() const;
};

bool operator==(UserGroupCreation const& l, UserGroupCreation const& r);
bool operator!=(UserGroupCreation const& l, UserGroupCreation const& r);

UserGroupCreation deserializeUserGroupCreation(gsl::span<uint8_t const> data);

std::uint8_t* to_serialized(std::uint8_t* it, UserGroupCreation const& dc);

std::size_t serialized_size(UserGroupCreation const& dc);

void to_json(nlohmann::json& j, UserGroupCreation const& dc);
}
