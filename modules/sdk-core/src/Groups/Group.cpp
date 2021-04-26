#include <Tanker/Groups/Group.hpp>

#include <Tanker/Errors/AssertionError.hpp>

using Tanker::Trustchain::GroupId;

namespace Tanker
{
bool operator==(InternalGroup const& l, InternalGroup const& r)
{
  return std::tie(
             l.id, l.signatureKeyPair, l.encryptionKeyPair, l.lastBlockHash, l.lastKeyRotationBlockHash) ==
         std::tie(
             r.id, r.signatureKeyPair, r.encryptionKeyPair, r.lastBlockHash, r.lastKeyRotationBlockHash);
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
    Crypto::Hash const& lastBlockHash,
    Crypto::Hash const& lastKeyRotationBlockHash)
  : id(id),
    publicSignatureKey(publicSignatureKey),
    encryptedPrivateSignatureKey(enc),
    publicEncryptionKey(publicEncryptionKey),
    lastBlockHash(lastBlockHash),
    lastKeyRotationBlockHash(lastKeyRotationBlockHash)
{
}

BaseGroup::BaseGroup(InternalGroup const& g)
  : _id(g.id),
    _lastBlockHash(g.lastBlockHash),
    _lastKeyRotationBlockHash(g.lastKeyRotationBlockHash),
    _publicSignatureKey(g.signatureKeyPair.publicKey),
    _publicEncryptionKey(g.encryptionKeyPair.publicKey)
{
}

BaseGroup::BaseGroup(ExternalGroup const& g)
  : _id(g.id),
    _lastBlockHash(g.lastBlockHash),
    _lastKeyRotationBlockHash(g.lastKeyRotationBlockHash),
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

Crypto::Hash const& BaseGroup::lastKeyRotationBlockHash() const
{
  return _lastKeyRotationBlockHash;
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
                  l.lastBlockHash,
                  l.lastKeyRotationBlockHash) == std::tie(r.id,
                                               r.publicSignatureKey,
                                               r.encryptedPrivateSignatureKey,
                                               r.publicEncryptionKey,
                                               r.lastBlockHash,
                                               r.lastKeyRotationBlockHash);
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

void updateLastKeyRotationBlockHash(Group& group, Crypto::Hash const& lastKeyRotationBlockHash)
{
  boost::variant2::visit([&](auto& g) { g.lastKeyRotationBlockHash = lastKeyRotationBlockHash; },
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

Trustchain::GroupId getGroupId(Group const& group)
{
  return boost::variant2::visit([](auto const& g) { return g.id; }, group);
}
}
