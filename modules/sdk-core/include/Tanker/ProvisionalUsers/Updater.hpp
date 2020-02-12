#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/ProvisionalUsers/SecretUser.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker::Users
{
class LocalUser;
class ContactStore;
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

tc::cotask<UsedSecretUser> extractKeysToStore(Users::LocalUser const& localUser,
                                              Entry const& entry);

tc::cotask<std::vector<UsedSecretUser>> processClaimEntries(
    Users::LocalUser const& userKeyStore,
    Users::ContactStore const& contactStore,
    std::vector<Trustchain::ServerEntry> const& serverEntries);
}
