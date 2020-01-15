#pragma once

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/Crypto/SealedEncryptionKeyPair.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
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
    Trustchain::ServerEntry const& serverEntry);

std::optional<Crypto::SealedEncryptionKeyPair> extractEncryptedUserKey(
    Trustchain::Actions::DeviceCreation const& deviceCreation);

std::optional<Crypto::SealedEncryptionKeyPair> extractEncryptedUserKey(
    Trustchain::Actions::DeviceRevocation const& deviceRevocation,
    Trustchain::DeviceId const& selfDeviceId);

std::tuple<Users::User, std::vector<Crypto::SealedEncryptionKeyPair>>
extractUserSealedKeys(DeviceKeys const& deviceKeys,
                      Trustchain::TrustchainId const& trustchainId,
                      Crypto::PublicSignatureKey const& trustchainPubSigKey,
                      gsl::span<Trustchain::ServerEntry const> entries);

std::vector<Crypto::EncryptionKeyPair> recoverUserKeys(
    Crypto::EncryptionKeyPair const& devEncKP,
    gsl::span<Crypto::SealedEncryptionKeyPair const> encryptedUserKeys);

Users::User applyDeviceCreationToUser(Tanker::Entry const& entry,
                                      std::optional<Users::User> previousUser);

Users::User applyDeviceRevocationToUser(Tanker::Entry const& entry,
                                        Users::User previousUser);

std::tuple<Crypto::PublicSignatureKey,
           Users::User,
           std::vector<Crypto::EncryptionKeyPair>>
processUserEntries(DeviceKeys const& deviceKeys,
                   Trustchain::TrustchainId const& trustchainId,
                   gsl::span<Trustchain::ServerEntry const> entries);

tc::cotask<void> updateLocalUser(
    gsl::span<Trustchain::ServerEntry const> serverEntries,
    Trustchain::TrustchainId const& trustchainId,
    LocalUser& localUser,
    ContactStore& contactStore);
}
}