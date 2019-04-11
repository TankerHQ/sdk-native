#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Types/GroupId.hpp>

#include <optional.hpp>

#include <cstdint>

namespace Tanker
{
struct Group
{
  GroupId id;
  Crypto::SignatureKeyPair signatureKeyPair;
  Crypto::EncryptionKeyPair encryptionKeyPair;
  Crypto::Hash lastBlockHash;
  uint64_t lastBlockIndex;
};

bool operator==(Group const& l, Group const& r);
bool operator!=(Group const& l, Group const& r);

struct ExternalGroup
{
  ExternalGroup() = default;
  ExternalGroup(ExternalGroup const&) = default;
  ExternalGroup(ExternalGroup&&) = default;
  ExternalGroup& operator=(ExternalGroup const&) = default;
  ExternalGroup& operator=(ExternalGroup&&) = default;
  ExternalGroup(GroupId const&,
                Crypto::PublicSignatureKey const&,
                nonstd::optional<Crypto::SealedPrivateSignatureKey> const&,
                Crypto::PublicEncryptionKey const&,
                Crypto::Hash const&,
                uint64_t lastBlockIndex);
  ExternalGroup(Group const&);

  GroupId id;
  Crypto::PublicSignatureKey publicSignatureKey;
  nonstd::optional<Crypto::SealedPrivateSignatureKey>
      encryptedPrivateSignatureKey;
  Crypto::PublicEncryptionKey publicEncryptionKey;
  Crypto::Hash lastBlockHash;
  uint64_t lastBlockIndex;
};

bool operator==(ExternalGroup const& l, ExternalGroup const& r);
bool operator!=(ExternalGroup const& l, ExternalGroup const& r);
}
