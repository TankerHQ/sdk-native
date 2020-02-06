#include <Tanker/Users/Device.hpp>

#include <tuple>

namespace Tanker::Users
{
Device::Device(Trustchain::DeviceId const& id,
               Trustchain::UserId const& userId,
               Crypto::PublicSignatureKey const& publicSignatureKey,
               Crypto::PublicEncryptionKey const& publicEncryptionKey,
               bool isGhostDevice,
               bool isRevoked)
  : _id(id),
    _userId(userId),
    _publicSignatureKey(publicSignatureKey),
    _publicEncryptionKey(publicEncryptionKey),
    _isGhostDevice(isGhostDevice),
    _isRevoked(isRevoked)
{
}

Trustchain::DeviceId const& Device::id() const
{
  return _id;
}

Trustchain::UserId const& Device::userId() const
{
  return _userId;
}

bool const& Device::isGhostDevice() const
{
  return _isGhostDevice;
}

void Device::setRevoked()
{
  _isRevoked = true;
}

bool const& Device::isRevoked() const
{
  return _isRevoked;
}

Crypto::PublicSignatureKey const& Device::publicSignatureKey() const
{
  return _publicSignatureKey;
}

Crypto::PublicEncryptionKey const& Device::publicEncryptionKey() const
{
  return _publicEncryptionKey;
}

bool operator==(Device const& l, Device const& r)
{
  return std::tie(l.id(),
                  l.userId(),
                  l.publicSignatureKey(),
                  l.publicEncryptionKey(),
                  l.isGhostDevice(),
                  l.isRevoked()) == std::tie(r.id(),
                                             r.userId(),
                                             r.publicSignatureKey(),
                                             r.publicEncryptionKey(),
                                             r.isGhostDevice(),
                                             r.isRevoked());
}

bool operator!=(Device const& l, Device const& r)
{
  return !(l == r);
}

bool operator<(Device const& l, Device const& r)
{
  return l.id() < r.id();
}
}
