#include <Tanker/ReceiveKey.hpp>

#include <Tanker/ContactStore.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Groups/GroupAccessor.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/ProvisionalUserKeysStore.hpp>
#include <Tanker/ResourceKeyStore.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToDevice.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToUser.hpp>
#include <Tanker/Trustchain/Actions/KeyPublish/ToUserGroup.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/ServerEntry.hpp>
#include <Tanker/UserKeyStore.hpp>

#include <tconcurrent/coroutine.hpp>

TLOG_CATEGORY("ReceiveKey");

using namespace Tanker::Trustchain::Actions;
using namespace Tanker::Errors;

namespace Tanker
{
namespace ReceiveKey
{
tc::cotask<void> onKeyToDeviceReceived(
    ContactStore const& contactStore,
    ResourceKeyStore& resourceKeyStore,
    Crypto::PrivateEncryptionKey const& selfDevicePrivateEncryptionKey,
    Entry const& entry)
{
  auto const& keyPublish =
      entry.action.get<KeyPublish>().get<KeyPublishToDevice>();
  Trustchain::DeviceId senderId{entry.author.begin(), entry.author.end()};

  auto const senderDevice = TC_AWAIT(contactStore.findDevice(senderId)).value();

  auto const key = Crypto::asymDecrypt<Crypto::SymmetricKey>(
      keyPublish.encryptedSymmetricKey(),
      senderDevice.publicEncryptionKey,
      selfDevicePrivateEncryptionKey);

  TC_AWAIT(resourceKeyStore.putKey(keyPublish.resourceId(), key));
}

namespace
{
tc::cotask<void> decryptAndStoreKey(
    ResourceKeyStore& resourceKeyStore,
    UserKeyStore const& userKeyStore,
    GroupAccessor&,
    ProvisionalUserKeysStore const&,
    Trustchain::Actions::KeyPublishToUser const& keyPublishToUser)
{
  auto const& recipientPublicKey =
      keyPublishToUser.recipientPublicEncryptionKey();
  auto const userKeyPair =
      TC_AWAIT(userKeyStore.getKeyPair(recipientPublicKey));

  auto const key =
      Crypto::sealDecrypt(keyPublishToUser.sealedSymmetricKey(), userKeyPair);

  TC_AWAIT(resourceKeyStore.putKey(keyPublishToUser.resourceId(), key));
}

tc::cotask<void> decryptAndStoreKey(
    ResourceKeyStore& resourceKeyStore,
    UserKeyStore const&,
    GroupAccessor& groupAccessor,
    ProvisionalUserKeysStore const&,
    Trustchain::Actions::KeyPublishToUserGroup const& keyPublishToUserGroup)
{
  auto const& recipientPublicKey =
      keyPublishToUserGroup.recipientPublicEncryptionKey();
  auto const group = TC_AWAIT(groupAccessor.getInternalGroup(recipientPublicKey));

  if (!group)
  {
    throw formatEx(Errc::InternalError,
                   "received a KeyPublish for a group we are not "
                   "in (public encryption "
                   "key: {})",
                   recipientPublicKey);
  }

  auto const key = Crypto::sealDecrypt(
      keyPublishToUserGroup.sealedSymmetricKey(), group->encryptionKeyPair);

  TC_AWAIT(resourceKeyStore.putKey(keyPublishToUserGroup.resourceId(), key));
}

tc::cotask<void> decryptAndStoreKey(
    ResourceKeyStore& resourceKeyStore,
    UserKeyStore const&,
    GroupAccessor&,
    ProvisionalUserKeysStore const& provisionalUserKeysStore,
    KeyPublishToProvisionalUser const& keyPublishToProvisionalUser)
{
  auto const provisionalUserKeys =
      TC_AWAIT(provisionalUserKeysStore.findProvisionalUserKeys(
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

tc::cotask<void> decryptAndStoreKey(
    ResourceKeyStore& resourceKeyStore,
    UserKeyStore const& userKeyStore,
    GroupAccessor&,
    ProvisionalUserKeysStore const& provisionalUserKeysStore,
    Trustchain::Actions::KeyPublishToDevice const& keyPublishToUser)
{
  throw AssertionError(
      "invalid nature in decryptAndStoreKey: KeyPublishToDevice");
}
}

tc::cotask<void> decryptAndStoreKey(
    ResourceKeyStore& resourceKeyStore,
    UserKeyStore const& userKeyStore,
    GroupAccessor& groupAccessor,
    ProvisionalUserKeysStore const& provisionalUserKeysStore,
    KeyPublish const& kp)
{
  TC_AWAIT(kp.visit([&](auto const& val) -> tc::cotask<void> {
    TC_AWAIT(decryptAndStoreKey(resourceKeyStore,
                                userKeyStore,
                                groupAccessor,
                                provisionalUserKeysStore,
                                val));
  }));
}
}
}
