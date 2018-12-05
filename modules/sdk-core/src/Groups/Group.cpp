#include <Tanker/Groups/Group.hpp>

namespace Tanker
{
bool operator==(Group const& l, Group const& r)
{
  return std::tie(l.id,
                  l.signatureKeyPair,
                  l.encryptionKeyPair,
                  l.lastBlockHash,
                  l.lastBlockIndex) == std::tie(r.id,
                                                r.signatureKeyPair,
                                                r.encryptionKeyPair,
                                                r.lastBlockHash,
                                                r.lastBlockIndex);
}

bool operator!=(Group const& l, Group const& r)
{
  return !(l == r);
}

ExternalGroup::ExternalGroup(
    GroupId const& id,
    Crypto::PublicSignatureKey const& publicSignatureKey,
    nonstd::optional<Crypto::SealedPrivateSignatureKey> const& enc,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::Hash const& lastBlockHash,
    uint64_t lastBlockIndex)
  : id(id),
    publicSignatureKey(publicSignatureKey),
    encryptedPrivateSignatureKey(enc),
    publicEncryptionKey(publicEncryptionKey),
    lastBlockHash(lastBlockHash),
    lastBlockIndex(lastBlockIndex)
{
}

ExternalGroup::ExternalGroup(Group const& group)
  : id(group.id),
    publicSignatureKey(group.signatureKeyPair.publicKey),
    encryptedPrivateSignatureKey(nonstd::nullopt),
    publicEncryptionKey(group.encryptionKeyPair.publicKey),
    lastBlockHash(group.lastBlockHash),
    lastBlockIndex(group.lastBlockIndex)
{
}

bool operator==(ExternalGroup const& l, ExternalGroup const& r)
{
  return std::tie(l.id,
                  l.publicSignatureKey,
                  l.encryptedPrivateSignatureKey,
                  l.publicEncryptionKey,
                  l.lastBlockHash,
                  l.lastBlockIndex) == std::tie(r.id,
                                                r.publicSignatureKey,
                                                r.encryptedPrivateSignatureKey,
                                                r.publicEncryptionKey,
                                                r.lastBlockHash,
                                                r.lastBlockIndex);
}

bool operator!=(ExternalGroup const& l, ExternalGroup const& r)
{
  return !(l == r);
}
}
