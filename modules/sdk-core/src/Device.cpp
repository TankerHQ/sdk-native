#include <Tanker/Device.hpp>

#include <tuple>

namespace Tanker
{
bool operator==(Device const& l, Device const& r)
{
  return std::tie(l.id,
                  l.createdAtBlkIndex,
                  l.revokedAtBlkIndex,
                  l.publicSignatureKey,
                  l.publicEncryptionKey,
                  l.isGhostDevice) == std::tie(r.id,
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
