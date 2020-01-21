#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/Context.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

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
Entry verifyDeviceCreation(
    Trustchain::ServerEntry const& serverEntry,
    Crypto::PublicSignatureKey const& trustchainPubSigKey);

Entry verifyDeviceCreation(
    Trustchain::ServerEntry const& serverEntry,
    Trustchain::Context const& context,
    std::optional<Users::User> const& user);
}
}
