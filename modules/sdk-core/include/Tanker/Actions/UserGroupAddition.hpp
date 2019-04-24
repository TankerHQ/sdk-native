#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Groups/GroupEncryptedKey.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <gsl-lite.hpp>
#include <nlohmann/json_fwd.hpp>
#include <optional.hpp>

#include <cstddef>
#include <vector>

namespace Tanker
{
struct UserGroupAddition
{
  using GroupEncryptedKeys = std::vector<GroupEncryptedKey>;

  Trustchain::GroupId groupId;
  Crypto::Hash previousGroupBlock;
  GroupEncryptedKeys encryptedGroupPrivateEncryptionKeysForUsers;
  Crypto::Signature selfSignatureWithCurrentKey;

  Trustchain::Actions::Nature nature() const;
  std::vector<Index> makeIndexes() const;
  std::vector<uint8_t> signatureData() const;
};

bool operator==(UserGroupAddition const& l, UserGroupAddition const& r);
bool operator!=(UserGroupAddition const& l, UserGroupAddition const& r);

UserGroupAddition deserializeUserGroupAddition(gsl::span<uint8_t const> data);

std::uint8_t* to_serialized(std::uint8_t* it, UserGroupAddition const& dc);

std::size_t serialized_size(UserGroupAddition const& dc);
void to_json(nlohmann::json& j, UserGroupAddition const& dc);
}
