#pragma once

namespace Tanker
{
struct UnverifiedEntry;
struct TrustchainCreation;
struct Device;
struct User;

namespace Verif
{
void verifyDeviceCreation(UnverifiedEntry const& entry,
                          TrustchainCreation const& author);

void verifyDeviceCreation(UnverifiedEntry const& entry,
                          Device const& author,
                          User const& user);
}
}
