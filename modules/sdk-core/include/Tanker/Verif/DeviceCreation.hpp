#pragma once

#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

namespace Tanker::Users
{
struct User;
struct Device;
}

namespace Tanker
{

namespace Verif
{
void verifyDeviceCreation(
    Trustchain::ServerEntry const& serverEntry,
    Trustchain::Actions::TrustchainCreation const& author);

void verifyDeviceCreation(Trustchain::ServerEntry const& serverEntry,
                          Users::Device const& author,
                          Users::User const& user);
}
}
