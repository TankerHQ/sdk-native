#include <Tanker/ReceiveKey.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/ADatabase.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Groups/GroupAccessor.hpp>
#include <Tanker/ResourceKeyStore.hpp>

#include "TestVerifier.hpp"
#include "TrustchainBuilder.hpp"

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include <doctest.h>

#include <mockaron/mockaron.hpp>

using namespace Tanker;
using namespace Tanker::Trustchain::Actions;

namespace
{
class GroupAccessorFake : public mockaron::mock_impl
{
public:
  std::vector<Group> groups;

  GroupAccessorFake()
  {
    MOCKARON_DECLARE_IMPL_CUSTOM(
        tc::cotask<nonstd::optional<Crypto::EncryptionKeyPair>>(
            Crypto::PublicEncryptionKey const&),
        nonstd::optional<Crypto::EncryptionKeyPair>,
        GroupAccessor,
        getEncryptionKeyPair);
  }

  nonstd::optional<Crypto::EncryptionKeyPair> getEncryptionKeyPair(
      Crypto::PublicEncryptionKey const& publicEncryptionKey)
  {
    auto const group = findGroup(publicEncryptionKey);
    if (group)
      if (auto const internalGroup =
              boost::variant2::get_if<InternalGroup>(&*group))
        return internalGroup->encryptionKeyPair;
    return nonstd::nullopt;
  }

private:
  nonstd::optional<Group> findGroup(
      Crypto::PublicEncryptionKey const& publicEncryptionKey)
  {
    auto const groupIt =
        std::find_if(groups.begin(), groups.end(), [&](auto const& g) {
          return getPublicEncryptionKey(g) == publicEncryptionKey;
        });

    if (groupIt == groups.end())
      return nonstd::nullopt;
    else
      return *groupIt;
  }
};
}

TEST_CASE("onKeyToDeviceReceived should process a key publish block")
{
  TrustchainBuilder builder;

  auto user = builder.makeUser1("receiver");
  builder.makeUser1("sender");

  auto const receiver = *builder.findUser("receiver");
  auto const receiverDevice = receiver.devices.front();

  auto const sender = *builder.findUser("sender");
  auto const senderDevice = sender.devices.front();

  auto const resourceMac = make<Trustchain::ResourceId>("resource resourceId");
  auto const resourceKey = make<Crypto::SymmetricKey>("the KEY");

  auto const keyPublishBlocks =
      builder.shareToDevice(senderDevice, receiver, resourceMac, resourceKey);
  assert(keyPublishBlocks.size() == 1);
  auto const keyPublishToDeviceEntry =
      toVerifiedEntry(blockToServerEntry(keyPublishBlocks[0]));

  auto const db = AWAIT(DataStore::createDatabase(":memory:"));
  ResourceKeyStore resourceKeyStore(db.get());
  auto const contactStore = builder.makeContactStoreWith({"sender"}, db.get());

  auto const receiverPrivateKey =
      receiverDevice.keys.encryptionKeyPair.privateKey;
  AWAIT_VOID(ReceiveKey::onKeyToDeviceReceived(*contactStore,
                                               resourceKeyStore,
                                               receiverPrivateKey,
                                               keyPublishToDeviceEntry));

  CHECK(AWAIT(resourceKeyStore.getKey(resourceMac)) == resourceKey);
}

TEST_CASE("decryptAndStoreKey")
{
  TrustchainBuilder builder;
  builder.makeUser3("receiver");
  builder.makeUser3("sender");

  auto const receiver = *builder.findUser("receiver");

  auto const sender = *builder.findUser("sender");
  auto const senderDevice = sender.devices.front();

  auto const resourceMac = make<Trustchain::ResourceId>("resource resourceId");
  auto const resourceKey = make<Crypto::SymmetricKey>("the KEY");

  SUBCASE("should process a key publish to user block")
  {
    auto const keyPublishBlock =
        builder.shareToUser(senderDevice, receiver, resourceMac, resourceKey);
    auto const keyPublishToUserEntry =
        toVerifiedEntry(blockToServerEntry(keyPublishBlock));

    auto const db = AWAIT(DataStore::createDatabase(":memory:"));
    auto const receiverKeyStore = builder.makeUserKeyStore(receiver, db.get());
    mockaron::mock<GroupAccessor, GroupAccessorFake> receiverGroupAccessor;
    ProvisionalUserKeysStore const receiverProvisionalUserKeysStore(db.get());
    ResourceKeyStore resourceKeyStore(db.get());

    AWAIT_VOID(ReceiveKey::decryptAndStoreKey(
        resourceKeyStore,
        *receiverKeyStore,
        receiverGroupAccessor.get(),
        receiverProvisionalUserKeysStore,
        keyPublishToUserEntry.action.get<KeyPublish>()));

    CHECK(AWAIT(resourceKeyStore.getKey(resourceMac)) == resourceKey);
  }

  SUBCASE("should process a key publish to group block")
  {
    auto const group = builder.makeGroup(receiver.devices[0], {receiver});

    auto const keyPublishBlock = builder.shareToUserGroup(
        senderDevice, group.group, resourceMac, resourceKey);
    auto const keyPublishToUserGroupEntry =
        toVerifiedEntry(blockToServerEntry(keyPublishBlock));

    auto const db = AWAIT(DataStore::createDatabase(":memory:"));
    auto const receiverKeyStore = builder.makeUserKeyStore(receiver, db.get());
    mockaron::mock<GroupAccessor, GroupAccessorFake> receiverGroupAccessor;
    receiverGroupAccessor.get_mock_impl().groups =
        builder.getGroupsOfUser(receiver);
    ProvisionalUserKeysStore const receiverProvisionalUserKeysStore(db.get());
    ResourceKeyStore resourceKeyStore(db.get());

    AWAIT_VOID(ReceiveKey::decryptAndStoreKey(
        resourceKeyStore,
        *receiverKeyStore,
        receiverGroupAccessor.get(),
        receiverProvisionalUserKeysStore,
        keyPublishToUserGroupEntry.action.get<KeyPublish>()));

    CHECK(AWAIT(resourceKeyStore.getKey(resourceMac)) == resourceKey);
  }

  SUBCASE("should process a key publish to provisional user")
  {
    auto const provisionalUser = builder.makeProvisionalUser("bob@gmail.com");

    auto const keyPublishBlock =
        builder.shareToProvisionalUser(senderDevice,
                                       provisionalUser.publicProvisionalUser,
                                       resourceMac,
                                       resourceKey);
    auto const keyPublishToProvisionalUserEntry =
        toVerifiedEntry(blockToServerEntry(keyPublishBlock));

    auto const db = AWAIT(DataStore::createDatabase(":memory:"));
    auto const receiverKeyStore = builder.makeUserKeyStore(receiver, db.get());
    mockaron::mock<GroupAccessor, GroupAccessorFake> receiverGroupAccessor;
    auto const receiverProvisionalUserKeysStore =
        builder.makeProvisionalUserKeysStoreWith({provisionalUser}, db.get());
    ResourceKeyStore resourceKeyStore(db.get());

    AWAIT_VOID(ReceiveKey::decryptAndStoreKey(
        resourceKeyStore,
        *receiverKeyStore,
        receiverGroupAccessor.get(),
        *receiverProvisionalUserKeysStore,
        keyPublishToProvisionalUserEntry.action.get<KeyPublish>()));

    CHECK(AWAIT(resourceKeyStore.getKey(resourceMac)) == resourceKey);
  }
}
