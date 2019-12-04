#pragma once

#include <Tanker/ContactStore.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/UserKeyStore.hpp>

#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
namespace ProvisionalUsers
{
namespace Updater
{
struct SecretProvisionalUser
{
  Crypto::PublicSignatureKey appSignaturePublicKey;
  Crypto::PublicSignatureKey tankerSignaturePublicKey;
  Crypto::EncryptionKeyPair appEncryptionKeyPair;
  Crypto::EncryptionKeyPair tankerEncryptionKeyPair;
};

tc::cotask<SecretProvisionalUser> extractKeysToStore(
    UserKeyStore const& userKeyStore, Entry const& entry);

tc::cotask<std::vector<SecretProvisionalUser>> processClaimEntries(
    ContactStore const& contactStore,
    UserKeyStore const& userKeyStore,
    std::vector<Trustchain::ServerEntry> const& serverEntries);
}
}
}
