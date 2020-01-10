#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

#include <optional>

namespace Tanker::Users
{
struct User;
}

namespace Tanker::Verif
{
Entry verifyDeviceRevocation(Trustchain::ServerEntry const& serverEntry,
                             std::optional<Users::User> const& user);
}
