#include <Tanker/ProvisionalUsers/Accessor.hpp>

#include <Tanker/Log/Log.hpp>
#include <Tanker/ProvisionalUsers/IRequester.hpp>
#include <Tanker/ProvisionalUsers/ProvisionalUserKeysStore.hpp>
#include <Tanker/ProvisionalUsers/Updater.hpp>
#include <Tanker/Trustchain/GroupId.hpp>
#include <Tanker/Users/ILocalUserAccessor.hpp>
#include <Tanker/Users/LocalUser.hpp>

TLOG_CATEGORY("ProvisionalUsersAccessor");

using Tanker::Trustchain::GroupId;

namespace Tanker::ProvisionalUsers
{
Accessor::Accessor(IRequester* requester,
                   Users::IUserAccessor* userAccessor,
                   Users::ILocalUserAccessor* localUserAccessor,
                   ProvisionalUserKeysStore* provisionalUserKeysStore)
  : _requester(requester),
    _userAccessor(userAccessor),
    _localUserAccessor(localUserAccessor),
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
  auto const blocks =
      TC_AWAIT(_requester->getClaimBlocks(_localUserAccessor->get().userId()));
  auto const toStore = TC_AWAIT(Updater::processClaimEntries(
      *_localUserAccessor, *_userAccessor, blocks));

  for (auto const& [appSignaturePublicKey,
                    tankerSignaturePublicKey,
                    appEncryptionKeyPair,
                    tankerEncryptionKeyPair] : toStore)
    TC_AWAIT(_provisionalUserKeysStore->putProvisionalUserKeys(
        appSignaturePublicKey,
        tankerSignaturePublicKey,
        {appEncryptionKeyPair, tankerEncryptionKeyPair}));
}
}
