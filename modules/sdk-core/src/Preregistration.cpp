#include <Tanker/Preregistration.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Groups/GroupUpdater.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>

TLOG_CATEGORY("Preregistration");

using Tanker::Trustchain::Actions::ProvisionalIdentityClaim;

namespace Tanker
{
namespace Preregistration
{
namespace
{
struct SecretProvisionalUserToStore
{
  Crypto::PublicSignatureKey appSignaturePublicKey;
  Crypto::PublicSignatureKey tankerSignaturePublicKey;
  Crypto::EncryptionKeyPair appEncryptionKeyPair;
  Crypto::EncryptionKeyPair tankerEncryptionKeyPair;
};

tc::cotask<SecretProvisionalUserToStore> extractKeysToStore(
    UserKeyStore& userKeyStore, Entry const& entry)
{
  auto const& provisionalIdentityClaim =
      entry.action.get<ProvisionalIdentityClaim>();

  auto const userKeyPair = TC_AWAIT(userKeyStore.findKeyPair(
      provisionalIdentityClaim.userPublicEncryptionKey()));

  if (!userKeyPair)
    throw Error::UserKeyNotFound("can't find user key for claim decryption");

  auto const provisionalIdentityKeys = Crypto::sealDecrypt(
      provisionalIdentityClaim.sealedPrivateEncryptionKeys(), *userKeyPair);

  // this size is ensured because the encrypted buffer has a fixed size
  assert(provisionalIdentityKeys.size() ==
         2 * Crypto::PrivateEncryptionKey::arraySize);

  auto const appEncryptionKeyPair =
      Crypto::makeEncryptionKeyPair(Crypto::PrivateEncryptionKey(
          gsl::make_span(provisionalIdentityKeys)
              .subspan(0, Crypto::PrivateEncryptionKey::arraySize)));
  auto const tankerEncryptionKeyPair =
      Crypto::makeEncryptionKeyPair(Crypto::PrivateEncryptionKey(
          gsl::make_span(provisionalIdentityKeys)
              .subspan(Crypto::PrivateEncryptionKey::arraySize)));

  TC_RETURN((SecretProvisionalUserToStore{
      provisionalIdentityClaim.appSignaturePublicKey(),
      provisionalIdentityClaim.tankerSignaturePublicKey(),
      appEncryptionKeyPair,
      tankerEncryptionKeyPair}));
}

tc::cotask<void> decryptPendingGroups(
    GroupStore& groupStore, SecretProvisionalUserToStore const& toStore)
{
  auto const pendingGroups =
      TC_AWAIT(groupStore.findExternalGroupsByProvisionalUser(
          toStore.appSignaturePublicKey, toStore.tankerSignaturePublicKey));

  for (auto const& pendingGroup : pendingGroups)
  {
    if (pendingGroup.provisionalUsers.size() != 1)
      throw std::runtime_error(
          "assertion failure: the group returned by "
          "findExternalGroupsByProvisionalUser should "
          "only contain the provisional user it was requested with");

    TINFO("Decrypting group key for group {} with claim {} {}",
          pendingGroup.id,
          toStore.appSignaturePublicKey,
          toStore.tankerSignaturePublicKey);

    auto const groupPrivateEncryptionKey = Crypto::sealDecrypt(
        Crypto::sealDecrypt(pendingGroup.provisionalUsers.front()
                                .encryptedPrivateEncryptionKey(),
                            toStore.tankerEncryptionKeyPair),
        toStore.appEncryptionKeyPair);
    TC_AWAIT(GroupUpdater::applyGroupPrivateKey(
        groupStore, pendingGroup, groupPrivateEncryptionKey));
  }
}
}

tc::cotask<void> applyEntry(UserKeyStore& userKeyStore,
                            ProvisionalUserKeysStore& provisionalUserKeysStore,
                            GroupStore& groupStore,
                            Entry const& entry)
{
  auto const toStore = TC_AWAIT(extractKeysToStore(userKeyStore, entry));

  TC_AWAIT(decryptPendingGroups(groupStore, toStore));

  TC_AWAIT(provisionalUserKeysStore.putProvisionalUserKeys(
      toStore.appSignaturePublicKey,
      toStore.tankerSignaturePublicKey,
      {toStore.appEncryptionKeyPair, toStore.tankerEncryptionKeyPair}));
}
}
}
