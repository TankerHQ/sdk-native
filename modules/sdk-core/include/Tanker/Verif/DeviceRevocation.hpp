#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

namespace Tanker::Users
{
struct User;
}

namespace Tanker::Verif
{
Entry verifyDeviceRevocation(Trustchain::ServerEntry const& serverEntry,
                             Users::User const& user);
}
