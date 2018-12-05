#pragma once

namespace Tanker
{
struct UnverifiedEntry;
struct TrustchainCreation;
struct Device;
struct User;

namespace Verif
{
void verifyDeviceRevocation(UnverifiedEntry const& entry,
                            Device const& author,
                            Device const& target,
                            User const& user);
}
}
