#include <Tanker/Trustchain/Actions/DeviceCreation/v1.hpp>

#include <Tanker/Crypto/Crypto.hpp>

#include <algorithm>
#include <tuple>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
DeviceCreation1::DeviceCreation1(
    Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
    UserId const& userId,
    Crypto::Signature const& delegationSignature,
    Crypto::PublicSignatureKey const& devicePublicSignatureKey,
    Crypto::PublicEncryptionKey const& devicePublicEncryptionKey)
  : _ephemeralPublicSignatureKey(ephemeralPublicSignatureKey),
    _userId(userId),
    _delegationSignature(delegationSignature),
    _publicSignatureKey(devicePublicSignatureKey),
    _publicEncryptionKey(devicePublicEncryptionKey)
{
}

DeviceCreation1::DeviceCreation1(
    Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
    UserId const& userId,
    Crypto::PublicSignatureKey const& devicePublicSignatureKey,
    Crypto::PublicEncryptionKey const& devicePublicEncryptionKey)
  : _ephemeralPublicSignatureKey(ephemeralPublicSignatureKey),
    _userId(userId),
    _publicSignatureKey(devicePublicSignatureKey),
    _publicEncryptionKey(devicePublicEncryptionKey)
{
}

Crypto::PublicSignatureKey const& DeviceCreation1::ephemeralPublicSignatureKey()
    const
{
  return _ephemeralPublicSignatureKey;
}

UserId const& DeviceCreation1::userId() const
{
  return _userId;
}

Crypto::Signature const& DeviceCreation1::delegationSignature() const
{
  return _delegationSignature;
}

Crypto::PublicSignatureKey const& DeviceCreation1::publicSignatureKey() const
{
  return _publicSignatureKey;
}

Crypto::PublicEncryptionKey const& DeviceCreation1::publicEncryptionKey() const
{
  return _publicEncryptionKey;
}

std::vector<std::uint8_t> DeviceCreation1::signatureData() const
{
  std::vector<std::uint8_t> toSign(Crypto::PublicSignatureKey::arraySize +
                                   UserId::arraySize);

  auto it = std::copy(_ephemeralPublicSignatureKey.begin(),
                      _ephemeralPublicSignatureKey.end(),
                      toSign.begin());
  std::copy(_userId.begin(), _userId.end(), it);
  return toSign;
}

Crypto::Signature const& DeviceCreation1::sign(
    Crypto::PrivateSignatureKey const& key)
{
  auto const toSign = signatureData();
  return _delegationSignature = Crypto::sign(toSign, key);
}

bool operator==(DeviceCreation1 const& lhs, DeviceCreation1 const& rhs)
{
  return std::tie(lhs.ephemeralPublicSignatureKey(),
                  lhs.userId(),
                  lhs.delegationSignature(),
                  lhs.publicSignatureKey(),
                  lhs.publicEncryptionKey()) ==
         std::tie(rhs.ephemeralPublicSignatureKey(),
                  rhs.userId(),
                  rhs.delegationSignature(),
                  rhs.publicSignatureKey(),
                  rhs.publicEncryptionKey());
}

bool operator!=(DeviceCreation1 const& lhs, DeviceCreation1 const& rhs)
{
  return !(lhs == rhs);
}
}
}
}
