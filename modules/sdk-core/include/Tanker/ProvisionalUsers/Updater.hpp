#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/ProvisionalUsers/SecretUser.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

#include <tconcurrent/coroutine.hpp>

#include <gsl-lite.hpp>

namespace Tanker::Users
{
class ILocalUserAccessor;
class IUserAccessor;
}

namespace Tanker::ProvisionalUsers::Updater
{

struct UsedSecretUser
{
  Crypto::PublicSignatureKey appSignaturePublicKey;
  Crypto::PublicSignatureKey tankerSignaturePublicKey;
  Crypto::EncryptionKeyPair appEncryptionKeyPair;
  Crypto::EncryptionKeyPair tankerEncryptionKeyPair;
};

tc::cotask<UsedSecretUser> extractKeysToStore(
    Users::ILocalUserAccessor& localUserAccessor, Entry const& entry);

tc::cotask<std::vector<UsedSecretUser>> processClaimEntries(
    Users::ILocalUserAccessor& localUserAccessor,
    Users::IUserAccessor& contactsAccessor,
    gsl::span<Trustchain::ServerEntry const> serverEntries);
}
