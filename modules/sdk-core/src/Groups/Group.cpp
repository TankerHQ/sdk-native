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
    Crypto::SealedPrivateSignatureKey const& enc,
    Crypto::PublicEncryptionKey const& publicEncryptionKey,
    Crypto::Hash const& lastBlockHash)
  : id(id),
    publicSignatureKey(publicSignatureKey),
    encryptedPrivateSignatureKey(enc),
    publicEncryptionKey(publicEncryptionKey),
    lastBlockHash(lastBlockHash)
{
}

BaseGroup::BaseGroup(InternalGroup const& g)
  : _id(g.id),
    _lastBlockHash(g.lastBlockHash),
    _publicSignatureKey(g.signatureKeyPair.publicKey),
    _publicEncryptionKey(g.encryptionKeyPair.publicKey)
{
}

BaseGroup::BaseGroup(ExternalGroup const& g)
  : _id(g.id),
    _lastBlockHash(g.lastBlockHash),
    _publicSignatureKey(g.publicSignatureKey),
    _publicEncryptionKey(g.publicEncryptionKey)
{
}

Trustchain::GroupId const& BaseGroup::id() const
{
  return _id;
}

Crypto::Hash const& BaseGroup::lastBlockHash() const
{
  return _lastBlockHash;
}

Crypto::PublicSignatureKey const& BaseGroup::publicSignatureKey() const
{
  return _publicSignatureKey;
}

Crypto::PublicEncryptionKey const& BaseGroup::publicEncryptionKey() const
{
  return _publicEncryptionKey;
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

BaseGroup extractBaseGroup(Group const& group)
{
  return boost::variant2::visit(
      [](auto&& g) { return BaseGroup{std::forward<decltype(g)>(g)}; }, group);
}

void updateLastGroupBlock(Group& group, Crypto::Hash const& lastBlockHash)
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
