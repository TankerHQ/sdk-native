#include <Tanker/Trustchain/Actions/DeviceCreation/v2.hpp>

#include <stdexcept>
#include <tuple>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
constexpr Nature DeviceCreation2::nature;

DeviceCreation2::DeviceCreation2(
    Crypto::PublicSignatureKey const& ephemeralPublicSignatureKey,
    UserId const& userId,
    Crypto::Signature const& delegationSignature,
    Crypto::PublicSignatureKey const& devicePublicSignatureKey,
    Crypto::PublicEncryptionKey const& devicePublicEncryptionKey,
    Crypto::Hash const& lastReset)
  : DeviceCreation1(ephemeralPublicSignatureKey,
                    userId,
                    delegationSignature,
                    devicePublicSignatureKey,
                    devicePublicEncryptionKey),
    _lastReset(lastReset)
{
}

DeviceCreation1 const& DeviceCreation2::asDeviceCreation1() const
{
  if (!_lastReset.is_null())
  {
    throw std::runtime_error{
        "cannot convert DeviceCreation2 to DeviceCreation1: lastReset field is "
        "not zero-filled"};
  }
  return static_cast<DeviceCreation1 const&>(*this);
}

Crypto::Hash const& DeviceCreation2::lastReset() const
{
  return _lastReset;
}

bool operator==(DeviceCreation2 const& lhs, DeviceCreation2 const& rhs)
{
  return std::tie(static_cast<DeviceCreation1 const&>(lhs), lhs.lastReset()) ==
         std::tie(static_cast<DeviceCreation1 const&>(rhs), rhs.lastReset());
}

bool operator!=(DeviceCreation2 const& lhs, DeviceCreation2 const& rhs)
{
  return !(lhs == rhs);
}
}
}
}
