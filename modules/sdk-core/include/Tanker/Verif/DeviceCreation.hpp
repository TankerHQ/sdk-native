#pragma once

#include <Tanker/Crypto/PublicSignatureKey.hpp>
#include <Tanker/Entry.hpp>
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
Entry verifyDeviceCreation(
    Trustchain::ServerEntry const& serverEntry,
    Crypto::PublicSignatureKey const& trustchainPubSigKey);

Entry verifyDeviceCreation(
    Trustchain::ServerEntry const& serverEntry,
    Trustchain::TrustchainId const& trustchainId,
    Crypto::PublicSignatureKey const& trustchainPubSigKey,
    Users::User const& user);
}
}
