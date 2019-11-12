#include <Tanker/Groups/Group.hpp>

#include <Tanker/Errors/AssertionError.hpp>

using Tanker::Trustchain::GroupId;

namespace Tanker
{
bool operator==(InternalGroup const& l, InternalGroup const& r)
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

bool operator!=(InternalGroup const& l, InternalGroup const& r)
{
  return !(l == r);
}

ExternalGroup::ExternalGroup(
    GroupId const& id,
    Crypto::PublicSignatureKey const& publicSignatureKey,
    nonstd::optional<Crypto::SealedPrivateSignatureKey> const& enc,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::Hash const& lastBlockHash,
    uint64_t lastBlockIndex,
    std::vector<GroupProvisionalUser> const& provisionalUsers)
  : id(id),
    publicSignatureKey(publicSignatureKey),
    encryptedPrivateSignatureKey(enc),
    publicEncryptionKey(publicEncryptionKey),
    lastBlockHash(lastBlockHash),
    lastBlockIndex(lastBlockIndex),
    provisionalUsers(provisionalUsers)
{
}

ExternalGroup::ExternalGroup(InternalGroup const& group)
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
                  l.lastBlockIndex,
                  l.provisionalUsers) ==
         std::tie(r.id,
                  r.publicSignatureKey,
                  r.encryptedPrivateSignatureKey,
                  r.publicEncryptionKey,
                  r.lastBlockHash,
                  r.lastBlockIndex,
                  r.provisionalUsers);
}

bool operator!=(ExternalGroup const& l, ExternalGroup const& r)
{
  return !(l == r);
}

ExternalGroup extractExternalGroup(Group const& group)
{
  return boost::variant2::visit(
      [](auto&& g) { return ExternalGroup(std::forward<decltype(g)>(g)); },
      group);
}

void updateLastGroupBlock(Group& group,
                          Crypto::Hash const& lastBlockHash,
                          uint64_t lastBlockIndex)
{
  boost::variant2::visit(
      [&](auto& g) {
        g.lastBlockHash = lastBlockHash;
        g.lastBlockIndex = lastBlockIndex;
      },
      group);
}
}
