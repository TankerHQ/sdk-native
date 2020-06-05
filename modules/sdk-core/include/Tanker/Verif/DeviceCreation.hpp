#pragma once

#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Context.hpp>

#include <optional>

namespace Tanker::Users
{
class User;
class Device;
}

namespace Tanker
{

namespace Verif
{
Trustchain::Actions::DeviceCreation verifyDeviceCreation(
    Trustchain::Actions::DeviceCreation const& action,
    Crypto::PublicSignatureKey const& trustchainPubSigKey);

Trustchain::Actions::DeviceCreation verifyDeviceCreation(
    Trustchain::Actions::DeviceCreation const& action,
    Trustchain::Context const& context,
    std::optional<Users::User> const& user);
}
}
