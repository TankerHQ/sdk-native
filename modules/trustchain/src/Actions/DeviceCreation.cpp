#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>

#include <algorithm>

namespace Tanker
{
namespace Trustchain
{
namespace Actions
{
DeviceCreation::DeviceCreation(v1 const& dc1) : _variant(dc1)
{
}

DeviceCreation::DeviceCreation(v3 const& dc3) : _variant(dc3)
{
}

Nature DeviceCreation::nature() const
{
  return mpark::visit([](auto const& a) { return a.nature; }, _variant);
}

Crypto::PublicSignatureKey const& DeviceCreation::ephemeralPublicSignatureKey()
    const
{
  return mpark::visit(
      [](auto const& a) -> decltype(auto) {
        return a.ephemeralPublicSignatureKey();
      },
      _variant);
}

UserId const& DeviceCreation::userId() const
{
  return mpark::visit(
      [](auto const& a) -> decltype(auto) { return a.userId(); }, _variant);
}

Crypto::Signature const& DeviceCreation::delegationSignature() const
{
  return mpark::visit(
      [](auto const& a) -> decltype(auto) { return a.delegationSignature(); },
      _variant);
}

Crypto::PublicSignatureKey const& DeviceCreation::publicSignatureKey() const
{
  return mpark::visit(
      [](auto const& a) -> decltype(auto) { return a.publicSignatureKey(); },
      _variant);
}

Crypto::PublicEncryptionKey const& DeviceCreation::publicEncryptionKey() const
{
  return mpark::visit(
      [](auto const& a) -> decltype(auto) { return a.publicEncryptionKey(); },
      _variant);
}

bool DeviceCreation::isGhostDevice() const
{
  if (auto dc3 = mpark::get_if<DeviceCreation3>(&_variant))
    return dc3->isGhostDevice();
  return false;
}

std::vector<std::uint8_t> DeviceCreation::signatureData() const
{
  return mpark::visit([&](auto const& val) { return val.signatureData(); },
                      _variant);
}

Crypto::Signature const& DeviceCreation::sign(
    Crypto::PrivateSignatureKey const& key)
{
  return mpark::visit(
      [&](auto& val) -> decltype(auto) { return val.sign(key); }, _variant);
}

bool operator==(DeviceCreation const& lhs, DeviceCreation const& rhs)
{
  return lhs._variant == rhs._variant;
}

bool operator!=(DeviceCreation const& lhs, DeviceCreation const& rhs)
{
  return !(lhs == rhs);
}
}
}
}
