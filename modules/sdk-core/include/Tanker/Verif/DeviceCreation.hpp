#pragma once

#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>

namespace Tanker
{
struct UnverifiedEntry;
struct Device;
struct User;

namespace Verif
{
void verifyDeviceCreation(
    UnverifiedEntry const& entry,
    Trustchain::Actions::TrustchainCreation const& author);

void verifyDeviceCreation(UnverifiedEntry const& entry,
                          Device const& author,
                          User const& user);
}
}
