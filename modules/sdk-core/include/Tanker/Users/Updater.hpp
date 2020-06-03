#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/SealedEncryptionKeyPair.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>
#include <Tanker/Trustchain/Context.hpp>
#include <Tanker/Trustchain/UserAction.hpp>
#include <Tanker/Users/User.hpp>

#include <gsl-lite.hpp>
#include <tconcurrent/coroutine.hpp>

#include <optional>
#include <tuple>

namespace Tanker
{
struct DeviceKeys;
}

namespace Tanker::Users
{
class LocalUser;
class ContactStore;

namespace Updater
{

Crypto::PublicSignatureKey extractTrustchainSignature(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::Actions::TrustchainCreation const& action);

std::optional<Crypto::SealedEncryptionKeyPair> extractEncryptedUserKey(
    Trustchain::Actions::DeviceCreation const& deviceCreation);

std::optional<Crypto::SealedEncryptionKeyPair> extractEncryptedUserKey(
    Trustchain::Actions::DeviceRevocation const& deviceRevocation,
    Trustchain::DeviceId const& selfDeviceId);

std::tuple<Users::User, std::vector<Crypto::SealedEncryptionKeyPair>>
processUserSealedKeys(DeviceKeys const& deviceKeys,
                      Trustchain::Context const& trustchainContext,
                      gsl::span<Trustchain::UserAction const> entries);

std::vector<Crypto::EncryptionKeyPair> recoverUserKeys(
    Crypto::EncryptionKeyPair const& devEncKP,
    gsl::span<Crypto::SealedEncryptionKeyPair const> encryptedUserKeys);

Users::User applyDeviceCreationToUser(
    Trustchain::Actions::DeviceCreation const& action,
    std::optional<Users::User> previousUser);

Users::User applyDeviceRevocationToUser(
    Trustchain::Actions::DeviceRevocation const& action,
    Users::User previousUser);

std::tuple<Trustchain::Context,
           Users::User,
           std::vector<Crypto::EncryptionKeyPair>>
processUserEntries(
    DeviceKeys const& deviceKeys,
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::Actions::TrustchainCreation const& trustchainCreation,
    gsl::span<Trustchain::UserAction const> entries);
}
}
