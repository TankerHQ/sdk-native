#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

#include <optional>

namespace Tanker::Users
{
struct User;
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
    Trustchain::TrustchainId const& trustchainId,
    Crypto::PublicSignatureKey const& trustchainPubSigKey,
    std::optional<Users::User> const& user);
}
}
