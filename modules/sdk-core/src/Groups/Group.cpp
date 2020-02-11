#include <Tanker/Groups/Group.hpp>

#include <Tanker/Errors/AssertionError.hpp>

using Tanker::Trustchain::GroupId;

namespace Tanker
{
bool operator==(InternalGroup const& l, InternalGroup const& r)
{
  return std::tie(
             l.id, l.signatureKeyPair, l.encryptionKeyPair, l.lastBlockHash) ==
         std::tie(
             r.id, r.signatureKeyPair, r.encryptionKeyPair, r.lastBlockHash);
}

bool operator!=(InternalGroup const& l, InternalGroup const& r)
{
  return !(l == r);
}

ExternalGroup::ExternalGroup(
    GroupId const& id,
    Crypto::PublicSignatureKey const& publicSignatureKey,
    std::optional<Crypto::SealedPrivateSignatureKey> const& enc,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::Hash const& lastBlockHash)
  : id(id),
    publicSignatureKey(publicSignatureKey),
    encryptedPrivateSignatureKey(enc),
    publicEncryptionKey(publicEncryptionKey),
    lastBlockHash(lastBlockHash)
{
}

ExternalGroup::ExternalGroup(InternalGroup const& group)
  : id(group.id),
    publicSignatureKey(group.signatureKeyPair.publicKey),
    encryptedPrivateSignatureKey(std::nullopt),
    publicEncryptionKey(group.encryptionKeyPair.publicKey),
    lastBlockHash(group.lastBlockHash)
{
}

bool operator==(ExternalGroup const& l, ExternalGroup const& r)
{
  return std::tie(l.id,
                  l.publicSignatureKey,
                  l.encryptedPrivateSignatureKey,
                  l.publicEncryptionKey,
                  l.lastBlockHash) == std::tie(r.id,
                                               r.publicSignatureKey,
                                               r.encryptedPrivateSignatureKey,
                                               r.publicEncryptionKey,
                                               r.lastBlockHash);
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
  boost::variant2::visit([&](auto& g) { g.lastBlockHash = lastBlockHash; },
                         group);
}

Crypto::PublicEncryptionKey getPublicEncryptionKey(Group const& group)
{
  struct Getter
  {
    auto operator()(ExternalGroup const& externalGroup) const
    {
      return externalGroup.publicEncryptionKey;
    }
    auto operator()(InternalGroup const& internalGroup) const
    {
      return internalGroup.encryptionKeyPair.publicKey;
    }
  };

  return boost::variant2::visit(Getter{}, group);
}
}
