#pragma once

#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

namespace Tanker
{
struct Device;
struct User;

namespace Verif
{
void verifyDeviceCreation(
    Trustchain::ServerEntry const& serverEntry,
    Trustchain::Actions::TrustchainCreation const& author);

void verifyDeviceCreation(Trustchain::ServerEntry const& serverEntry,
                          Device const& author,
                          User const& user);
}
}
