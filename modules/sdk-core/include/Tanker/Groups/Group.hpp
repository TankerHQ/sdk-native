#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/SealedPrivateSignatureKey.hpp>
#include <Tanker/Crypto/SignatureKeyPair.hpp>
#include <Tanker/Groups/GroupProvisionalUser.hpp>
#include <Tanker/Trustchain/GroupId.hpp>

#include <optional.hpp>

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
                nonstd::optional<Crypto::SealedPrivateSignatureKey> const&,
                Crypto::PublicEncryptionKey const&,
                Crypto::Hash const&,
                uint64_t lastBlockIndex,
                std::vector<GroupProvisionalUser> const& = {});
  ExternalGroup(InternalGroup const&);

  Trustchain::GroupId id;
  Crypto::PublicSignatureKey publicSignatureKey;
  nonstd::optional<Crypto::SealedPrivateSignatureKey>
      encryptedPrivateSignatureKey;
  Crypto::PublicEncryptionKey publicEncryptionKey;
  Crypto::Hash lastBlockHash;
  uint64_t lastBlockIndex;
  std::vector<GroupProvisionalUser> provisionalUsers;
};

bool operator==(ExternalGroup const& l, ExternalGroup const& r);
bool operator!=(ExternalGroup const& l, ExternalGroup const& r);

using Group = boost::variant2::variant<InternalGroup, ExternalGroup>;
}
