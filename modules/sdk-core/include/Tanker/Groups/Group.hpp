#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Groups/GroupProvisionalUser.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <optional>

#include <boost/variant2/variant.hpp>

#include <cstdint>

namespace Tanker
{
struct InternalGroup
{
  Trustchain::GroupId id;
  Crypto::SignatureKeyPair signatureKeyPair;
  Crypto::EncryptionKeyPair encryptionKeyPair;
  Crypto::Hash lastBlockHash;
  uint64_t lastBlockIndex;
};

bool operator==(InternalGroup const& l, InternalGroup const& r);
bool operator!=(InternalGroup const& l, InternalGroup const& r);

struct ExternalGroup
{
  ExternalGroup() = default;
  ExternalGroup(ExternalGroup const&) = default;
  ExternalGroup(ExternalGroup&&) = default;
  ExternalGroup& operator=(ExternalGroup const&) = default;
  ExternalGroup& operator=(ExternalGroup&&) = default;
  ExternalGroup(Trustchain::GroupId const&,
                Crypto::PublicSignatureKey const&,
                std::optional<Crypto::SealedPrivateSignatureKey> const&,
                Crypto::PublicEncryptionKey const&,
                Crypto::Hash const&,
                uint64_t lastBlockIndex);
  ExternalGroup(InternalGroup const&);

  Trustchain::GroupId id;
  Crypto::PublicSignatureKey publicSignatureKey;
  std::optional<Crypto::SealedPrivateSignatureKey>
      encryptedPrivateSignatureKey;
  Crypto::PublicEncryptionKey publicEncryptionKey;
  Crypto::Hash lastBlockHash;
  uint64_t lastBlockIndex;
};

bool operator==(ExternalGroup const& l, ExternalGroup const& r);
bool operator!=(ExternalGroup const& l, ExternalGroup const& r);

using Group = boost::variant2::variant<InternalGroup, ExternalGroup>;

ExternalGroup extractExternalGroup(Group const& group);

// optional has no .map()
inline std::optional<ExternalGroup> extractExternalGroup(
    std::optional<Group> const& group)
{
  if (!group)
    return std::nullopt;
  return extractExternalGroup(*group);
}

void updateLastGroupBlock(Group& group,
                          Crypto::Hash const& lastBlockHash,
                          uint64_t lastBlockIndex);
Crypto::PublicEncryptionKey getPublicEncryptionKey(Group const& group);
}
