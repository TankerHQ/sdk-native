#include <Tanker/Users/Device.hpp>

#include <tuple>

namespace Tanker::Users
{
Device::Device(Trustchain::DeviceId const& id,
               Trustchain::UserId const& userId,
               std::uint64_t createdAtBlkIndex,
               bool isGhostDevice,
               Crypto::PublicSignatureKey const& publicSignatureKey,
               Crypto::PublicEncryptionKey const& publicEncryptionKey)
  : Device(id,
           userId,
           createdAtBlkIndex,
           isGhostDevice,
           std::nullopt,
           publicSignatureKey,
           publicEncryptionKey)
{
}

Device::Device(Trustchain::DeviceId const& id,
               Trustchain::UserId const& userId,
               std::uint64_t createdAtBlkIndex,
               bool isGhostDevice,
               std::optional<std::uint64_t> revokedAtBlkIndex,
               Crypto::PublicSignatureKey const& publicSignatureKey,
               Crypto::PublicEncryptionKey const& publicEncryptionKey)
  : _id(id),
    _userId(userId),
    _createdAtBlkIndex(createdAtBlkIndex),
    _isGhostDevice(isGhostDevice),
    _revokedAtBlkIndex(revokedAtBlkIndex),
    _publicSignatureKey(publicSignatureKey),
    _publicEncryptionKey(publicEncryptionKey)
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

std::uint64_t const& Device::createdAtBlkIndex() const
{
  return _createdAtBlkIndex;
}

bool const& Device::isGhostDevice() const
{
  return _isGhostDevice;
}

std::optional<std::uint64_t> const& Device::revokedAtBlkIndex() const
{
  return _revokedAtBlkIndex;
}
void Device::setRevokedAtBlkIndex(std::uint64_t index)
{
  _revokedAtBlkIndex = index;
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
                  l.createdAtBlkIndex(),
                  l.revokedAtBlkIndex(),
                  l.publicSignatureKey(),
                  l.publicEncryptionKey(),
                  l.isGhostDevice()) == std::tie(r.id(),
                                                 r.userId(),
                                                 r.createdAtBlkIndex(),
                                                 r.revokedAtBlkIndex(),
                                                 r.publicSignatureKey(),
                                                 r.publicEncryptionKey(),
                                                 r.isGhostDevice());
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
