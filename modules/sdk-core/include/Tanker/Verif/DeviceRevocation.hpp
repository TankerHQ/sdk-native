#pragma once

#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>

#include <optional>

namespace Tanker::Users
{
class User;
}

namespace Tanker::Verif
{
Trustchain::Actions::DeviceRevocation verifyDeviceRevocation(
    Trustchain::Actions::DeviceRevocation const& action,
    std::optional<Users::User> const& user);
}
