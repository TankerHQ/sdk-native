#include <Tanker/Trustchain/Actions/DeviceCreation/v1.hpp>

#include <tuple>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
constexpr Nature DeviceCreation1::nature;

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
