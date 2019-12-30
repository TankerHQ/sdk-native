#include <Tanker/Users/Device.hpp>

#include <tuple>

namespace Tanker::Users
{
Device::Device(Trustchain::DeviceId const& id,
               Trustchain::UserId const& userId,
               uint64_t createdAtBlkIndex,
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
               uint64_t createdAtBlkIndex,
               bool isGhostDevice,
               std::optional<uint64_t> revokedAtBlkIndex,
               Crypto::PublicSignatureKey const& publicSignatureKey,
               Crypto::PublicEncryptionKey const& publicEncryptionKey)
  : id(id),
    userId(userId),
    createdAtBlkIndex(createdAtBlkIndex),
    isGhostDevice(isGhostDevice),
    revokedAtBlkIndex(revokedAtBlkIndex),
    publicSignatureKey(publicSignatureKey),
    publicEncryptionKey(publicEncryptionKey)
{
}

bool operator==(Device const& l, Device const& r)
{
  return std::tie(l.id,
                  l.userId,
                  l.createdAtBlkIndex,
                  l.revokedAtBlkIndex,
                  l.publicSignatureKey,
                  l.publicEncryptionKey,
                  l.isGhostDevice) == std::tie(r.id,
                                               r.userId,
                                               r.createdAtBlkIndex,
                                               r.revokedAtBlkIndex,
                                               r.publicSignatureKey,
                                               r.publicEncryptionKey,
                                               r.isGhostDevice);
}

bool operator!=(Device const& l, Device const& r)
{
  return !(l == r);
}
}
