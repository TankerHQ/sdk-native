#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Groups/GroupEncryptedKey.hpp>
#include <Tanker/Index.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Types/GroupId.hpp>
#include <Tanker/Types/UserId.hpp>

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

  GroupId groupId;
  Crypto::Hash previousGroupBlock;
  GroupEncryptedKeys encryptedGroupPrivateEncryptionKeysForUsers;
  Crypto::Signature selfSignatureWithCurrentKey;

  Nature nature() const;
  std::vector<Index> makeIndexes() const;
  std::vector<uint8_t> signatureData() const;
};

bool operator==(UserGroupAddition const& l, UserGroupAddition const& r);
bool operator!=(UserGroupAddition const& l, UserGroupAddition const& r);

UserGroupAddition deserializeUserGroupAddition(gsl::span<uint8_t const> data);

template <typename OutputIterator>
void to_serialized(OutputIterator it, UserGroupAddition const& dc)
{
  Serialization::serialize(it, dc.groupId);
  Serialization::serialize(it, dc.previousGroupBlock);
  Serialization::serialize(it, dc.encryptedGroupPrivateEncryptionKeysForUsers);
  Serialization::serialize(it, dc.selfSignatureWithCurrentKey);
}

std::size_t serialized_size(UserGroupAddition const& dc);
void to_json(nlohmann::json& j, UserGroupAddition const& dc);
}
