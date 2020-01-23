#include <Tanker/ProvisionalUsers/Accessor.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/ProvisionalUsers/Requests.hpp>
#include <Tanker/ProvisionalUsers/Updater.hpp>
#include <Tanker/Users/ContactStore.hpp>
#include <Tanker/Users/LocalUser.hpp>

TLOG_CATEGORY("ProvisionalUsersAccessor");

using Tanker::Trustchain::GroupId;

namespace Tanker::ProvisionalUsers
{
Accessor::Accessor(Client* client,
                   Users::ContactStore const* contactStore,
                   Users::LocalUser const* localUser,
                   ProvisionalUserKeysStore* provisionalUserKeysStore)
  : _client(client),
    _contactStore(contactStore),
    _localUser(localUser),
    _provisionalUserKeysStore(provisionalUserKeysStore)
{
}

tc::cotask<std::optional<ProvisionalUserKeys>>
Accessor::findEncryptionKeysFromCache(
    Crypto::PublicSignatureKey const& appPublicSigKey,
    Crypto::PublicSignatureKey const& tankerPublicSigKey)
{
  TC_RETURN(TC_AWAIT(_provisionalUserKeysStore->findProvisionalUserKeys(
      appPublicSigKey, tankerPublicSigKey)));
}

tc::cotask<std::optional<ProvisionalUserKeys>> Accessor::pullEncryptionKeys(
    Crypto::PublicSignatureKey const& appPublicSigKey,
    Crypto::PublicSignatureKey const& tankerPublicSigKey)
{
  auto const keys = TC_AWAIT(_provisionalUserKeysStore->findProvisionalUserKeys(
      appPublicSigKey, tankerPublicSigKey));

  if (keys)
    TC_RETURN(*keys);

  TC_AWAIT(refreshKeys());

  TC_RETURN(TC_AWAIT(_provisionalUserKeysStore->findProvisionalUserKeys(
      appPublicSigKey, tankerPublicSigKey)));
}

tc::cotask<void> Accessor::refreshKeys()
{
  auto const blocks = TC_AWAIT(Requests::getClaimBlocks(_client));
  auto const toStore = TC_AWAIT(
      Updater::processClaimEntries(*_localUser, *_contactStore, blocks));

  for (auto const& keys : toStore)
    TC_AWAIT(_provisionalUserKeysStore->putProvisionalUserKeys(
        keys.appSignaturePublicKey,
        keys.tankerSignaturePublicKey,
        {keys.appEncryptionKeyPair, keys.tankerEncryptionKeyPair}));
}
}
