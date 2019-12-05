#pragma once

#include <Tanker/Entry.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker::Users
{
class UserKeyStore;
class ContactStore;
}

namespace Tanker::ProvisionalUsers::Updater
{
struct SecretProvisionalUser
{
  Crypto::PublicSignatureKey appSignaturePublicKey;
  Crypto::PublicSignatureKey tankerSignaturePublicKey;
  Crypto::EncryptionKeyPair appEncryptionKeyPair;
  Crypto::EncryptionKeyPair tankerEncryptionKeyPair;
};

tc::cotask<SecretProvisionalUser> extractKeysToStore(
    Users::UserKeyStore const& userKeyStore, Entry const& entry);

tc::cotask<std::vector<SecretProvisionalUser>> processClaimEntries(
    Users::ContactStore const& contactStore,
    Users::UserKeyStore const& userKeyStore,
    std::vector<Trustchain::ServerEntry> const& serverEntries);
}
