#include <Tanker/ReceiveKey.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Groups/IAccessor.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/ProvisionalUsers/IAccessor.hpp>
#include <Tanker/ResourceKeyStore.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToUser.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToUserGroup.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/Users/LocalUserAccessor.hpp>

#include <tconcurrent/coroutine.hpp>

TLOG_CATEGORY("ReceiveKey");

using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Errors;

namespace Tanker
{
namespace ReceiveKey
{
namespace
{
tc::cotask<void> decryptAndStoreKey(
    ResourceKeyStore& resourceKeyStore,
    Users::ILocalUserAccessor& localUserAccessor,
    Groups::IAccessor&,
    ProvisionalUsers::IAccessor&,
    Trustchain::Actions::KeyPublishToUser const& keyPublishToUser)
{
  auto const& recipientPublicKey =
      keyPublishToUser.recipientPublicEncryptionKey();
  auto const userKeyPair =
      TC_AWAIT(localUserAccessor.pullUserKeyPair(recipientPublicKey));

  if (!userKeyPair)
    throw formatEx(Errc::InternalError,
                   "received a KeyPublish for user key we do not have "
                   "(public encryption key: {})",
                   recipientPublicKey);

  auto const key =
      Crypto::sealDecrypt(keyPublishToUser.sealedSymmetricKey(), *userKeyPair);

  TC_AWAIT(resourceKeyStore.putKey(keyPublishToUser.resourceId(), key));
}

tc::cotask<void> decryptAndStoreKey(
    ResourceKeyStore& resourceKeyStore,
    Users::ILocalUserAccessor&,
    Groups::IAccessor& groupAccessor,
    ProvisionalUsers::IAccessor&,
    Trustchain::Actions::KeyPublishToUserGroup const& keyPublishToUserGroup)
{
  auto const& recipientPublicKey =
      keyPublishToUserGroup.recipientPublicEncryptionKey();
  auto const encryptionKeyPair =
      TC_AWAIT(groupAccessor.getEncryptionKeyPair(recipientPublicKey));

  if (!encryptionKeyPair)
  {
    throw formatEx(Errc::InternalError,
                   "received a KeyPublish for a group we are not "
                   "in (public encryption key: {})",
                   recipientPublicKey);
  }

  auto const key = Crypto::sealDecrypt(
      keyPublishToUserGroup.sealedSymmetricKey(), *encryptionKeyPair);

  TC_AWAIT(resourceKeyStore.putKey(keyPublishToUserGroup.resourceId(), key));
}

tc::cotask<void> decryptAndStoreKey(
    ResourceKeyStore& resourceKeyStore,
    Users::ILocalUserAccessor&,
    Groups::IAccessor&,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    KeyPublishToProvisionalUser const& keyPublishToProvisionalUser)
{
  auto const provisionalUserKeys =
      TC_AWAIT(provisionalUsersAccessor.pullEncryptionKeys(
          keyPublishToProvisionalUser.appPublicSignatureKey(),
          keyPublishToProvisionalUser.tankerPublicSignatureKey()));

  if (!provisionalUserKeys)
  {
    throw formatEx(Errc::InternalError,
                   "received a KeyPublish for a provisional user we did not "
                   "claim (public encryption keys: {} {})",
                   keyPublishToProvisionalUser.appPublicSignatureKey(),
                   keyPublishToProvisionalUser.tankerPublicSignatureKey());
  }

  auto const encryptedKey = Crypto::sealDecrypt(
      keyPublishToProvisionalUser.twoTimesSealedSymmetricKey(),
      provisionalUserKeys->tankerKeys);
  auto const key =
      Crypto::sealDecrypt(encryptedKey, provisionalUserKeys->appKeys);

  TC_AWAIT(
      resourceKeyStore.putKey(keyPublishToProvisionalUser.resourceId(), key));
}
}

tc::cotask<void> decryptAndStoreKey(
    ResourceKeyStore& resourceKeyStore,
    Users::ILocalUserAccessor& localUserAccessor,
    Groups::IAccessor& groupAccessor,
    ProvisionalUsers::IAccessor& provisionalUsersAccessor,
    KeyPublish const& kp)
{
  TC_AWAIT(kp.visit([&](auto const& val) -> tc::cotask<void> {
    TC_AWAIT(decryptAndStoreKey(resourceKeyStore,
                                localUserAccessor,
                                groupAccessor,
                                provisionalUsersAccessor,
                                val));
  }));
}
}
}
