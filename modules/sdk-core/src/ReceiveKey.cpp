#include <Tanker/ReceiveKey.hpp>

#include <Tanker/ContactStore.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Groups/GroupStore.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/ResourceKeyStore.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/KeyPublishToDevice.hpp>
#include <Tanker/Trustchain/Actions/KeyPublishToUser.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/UnverifiedEntry.hpp>
#include <Tanker/UserKeyStore.hpp>

#include <mpark/variant.hpp>
#include <tconcurrent/coroutine.hpp>

TLOG_CATEGORY("ReceiveKey");

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
  auto const& keyPublish = mpark::get<Trustchain::Actions::KeyPublishToDevice>(
      entry.action.variant());
  Trustchain::DeviceId senderId{entry.author.begin(), entry.author.end()};

  auto const senderDevice = TC_AWAIT(contactStore.findDevice(senderId)).value();

  auto const key = Crypto::asymDecrypt<Crypto::SymmetricKey>(
      keyPublish.encryptedSymmetricKey(),
      senderDevice.publicEncryptionKey,
      selfDevicePrivateEncryptionKey);

  TC_AWAIT(resourceKeyStore.putKey(keyPublish.mac(), key));
}

namespace
{
tc::cotask<void> decryptAndStoreKeyForUser(
    ResourceKeyStore& resourceKeyStore,
    UserKeyStore const& userKeyStore,
    Trustchain::Actions::KeyPublishToUser const& keyPublishToUser)
{
  auto const& recipientPublicKey =
      keyPublishToUser.recipientPublicEncryptionKey();
  auto const userKeyPair =
      TC_AWAIT(userKeyStore.getKeyPair(recipientPublicKey));

  auto const key = Crypto::sealDecrypt<Crypto::SymmetricKey>(
      keyPublishToUser.sealedSymmetricKey(), userKeyPair);

  TC_AWAIT(resourceKeyStore.putKey(keyPublishToUser.mac(), key));
}

tc::cotask<void> decryptAndStoreKeyForGroup(
    ResourceKeyStore& resourceKeyStore,
    GroupStore const& groupStore,
    KeyPublishToUserGroup const& keyPublishToUserGroup)
{
  auto const& recipientPublicKey =
      keyPublishToUserGroup.recipientPublicEncryptionKey;
  auto const group =
      TC_AWAIT(groupStore.findFullByPublicEncryptionKey(recipientPublicKey));

  if (!group)
  {
    TERROR(
        "Received a keypublish for a group we are not in (public encryption "
        "key: {})",
        recipientPublicKey);
    TC_RETURN();
  }

  auto const key = Crypto::sealDecrypt<Crypto::SymmetricKey>(
      keyPublishToUserGroup.key, group->encryptionKeyPair);

  TC_AWAIT(resourceKeyStore.putKey(keyPublishToUserGroup.resourceId, key));
}
}

tc::cotask<void> decryptAndStoreKey(ResourceKeyStore& resourceKeyStore,
                                    UserKeyStore const& userKeyStore,
                                    GroupStore const& groupStore,
                                    Entry const& entry)
{
  if (auto const keyPublishToUser =
          mpark::get_if<Trustchain::Actions::KeyPublishToUser>(
              &entry.action.variant()))
    TC_AWAIT(decryptAndStoreKeyForUser(
        resourceKeyStore, userKeyStore, *keyPublishToUser));
  else if (auto const keyPublishToUserGroup =
               mpark::get_if<KeyPublishToUserGroup>(&entry.action.variant()))
    TC_AWAIT(decryptAndStoreKeyForGroup(
        resourceKeyStore, groupStore, *keyPublishToUserGroup));
}
}
}
