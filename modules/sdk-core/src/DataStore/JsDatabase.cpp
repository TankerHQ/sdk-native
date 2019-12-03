#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/DataStore/JsDatabase.hpp>
#include <Tanker/Emscripten/Helpers.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Enum.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <emscripten.h>
#include <emscripten/bind.h>

using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

TLOG_CATEGORY(Database);

using namespace Tanker::Emscripten;

namespace Tanker
{
namespace DataStore
{
class JsDatabaseInterface
{
public:
  virtual ~JsDatabaseInterface() = default;
  virtual emscripten::val putUserPrivateKey(
      emscripten::val const& publicKey, emscripten::val const& privateKey) = 0;
  virtual emscripten::val getUserKeyPair(emscripten::val const& publicKey) = 0;
  virtual emscripten::val getUserOptLastKeyPair() = 0;

  virtual emscripten::val findTrustchainLastIndex() = 0;
  virtual emscripten::val findTrustchainPublicSignatureKey() = 0;
  virtual emscripten::val setTrustchainLastIndex(
      emscripten::val const& idx) = 0;
  virtual emscripten::val setTrustchainPublicSignatureKey(
      emscripten::val const& idx) = 0;
  virtual emscripten::val addTrustchainEntry(emscripten::val const& entry) = 0;
  virtual emscripten::val findTrustchainEntry(
      emscripten::val const& resourceId) = 0;

  virtual emscripten::val putContact(emscripten::val const& userId,
                                     emscripten::val const& publicKey) = 0;
  virtual emscripten::val findContactUserKey(emscripten::val const& userId) = 0;
  virtual emscripten::val findContactUserIdByPublicEncryptionKey(
      emscripten::val const& publicEncryptionKey) = 0;
  virtual emscripten::val setContactPublicEncryptionKey(
      emscripten::val const& userId, emscripten::val const& userPublicKey) = 0;

  virtual emscripten::val putKeyPublishes(emscripten::val const& kps) = 0;
  virtual emscripten::val findKeyPublish(emscripten::val const& kp) = 0;

  virtual emscripten::val putResourceKey(emscripten::val const& resourceId,
                                         emscripten::val const& key) = 0;
  virtual emscripten::val findResourceKey(
      emscripten::val const& resourceId) = 0;

  virtual emscripten::val getDeviceKeys() = 0;
  virtual emscripten::val getDeviceId() = 0;
  virtual emscripten::val setDeviceKeys(emscripten::val const& deviceKeys) = 0;
  virtual emscripten::val setDeviceId(emscripten::val const& deviceId) = 0;

  virtual emscripten::val putDevice(emscripten::val const& userId,
                                    emscripten::val const& device) = 0;
  virtual emscripten::val findDevice(emscripten::val const& deviceId) = 0;
  virtual emscripten::val getDevicesOf(emscripten::val const& userId) = 0;
  virtual emscripten::val findDeviceUserId(emscripten::val const& deviceId) = 0;
  virtual emscripten::val updateDeviceRevokedAt(
      emscripten::val const& deviceId,
      emscripten ::val const& revokedAtBlkIndex) = 0;

  virtual emscripten::val putInternalGroup(emscripten::val const& group) = 0;
  virtual emscripten::val putExternalGroup(emscripten::val const& group) = 0;
  virtual emscripten::val putGroupProvisionalEncryptionKeys(
      emscripten::val const& groupid, emscripten::val const& keys) = 0;
  virtual emscripten::val putProvisionalUserKeys(
      emscripten::val const& provisionalUserKeys) = 0;
  virtual emscripten::val updateLastGroupBlock(
      emscripten::val const& groupId,
      emscripten::val const& lastBlockHash,
      emscripten::val const& lastBlockIndex) = 0;
  virtual emscripten::val findInternalGroupByGroupId(
      emscripten::val const& groupId) = 0;
  virtual emscripten::val findExternalGroupByGroupId(
      emscripten::val const& groupId) = 0;
  virtual emscripten::val findExternalGroupsByProvisionalUser(
      emscripten::val const& appSignaturePublicKey,
      emscripten::val const& tankerSignaturePublicKey) = 0;
  virtual emscripten::val findInternalGroupByGroupPublicEncryptionKey(
      emscripten::val const& publicEncryptionKey) = 0;
  virtual emscripten::val findExternalGroupByGroupPublicEncryptionKey(
      emscripten::val const& publicEncryptionKey) = 0;
  virtual emscripten::val findProvisionalUserKeys(
      emscripten::val const& appPublicSigKey,
      emscripten::val const& tankerPublicSigKey) = 0;
  virtual emscripten::val findProvisionalUserKeysByAppPublicEncryptionKey(
      emscripten::val const& appPublicEncKey) = 0;

  virtual emscripten::val nuke() = 0;

  virtual emscripten::val startTransaction() = 0;
  virtual emscripten::val commitTransaction() = 0;
  virtual emscripten::val rollbackTransaction() = 0;
};

namespace
{
class JsDatabaseInterfaceWrapper
  : public emscripten::wrapper<JsDatabaseInterface>
{
public:
  EMSCRIPTEN_WRAPPER(JsDatabaseInterfaceWrapper);

#define FORWARD_CALL0(name)              \
  emscripten::val name() override        \
  {                                      \
    return call<emscripten::val>(#name); \
  }
#define FORWARD_CALL1(name)                                \
  emscripten::val name(emscripten::val const& a1) override \
  {                                                        \
    return call<emscripten::val>(#name, a1);               \
  }
#define FORWARD_CALL2(name)                                                  \
  emscripten::val name(emscripten::val const& a1, emscripten::val const& a2) \
      override                                                               \
  {                                                                          \
    return call<emscripten::val>(#name, a1, a2);                             \
  }
#define FORWARD_CALL3(name)                                \
  emscripten::val name(emscripten::val const& a1,          \
                       emscripten::val const& a2,          \
                       emscripten::val const& a3) override \
  {                                                        \
    return call<emscripten::val>(#name, a1, a2, a3);       \
  }

  FORWARD_CALL2(putUserPrivateKey)
  FORWARD_CALL1(getUserKeyPair)
  FORWARD_CALL0(getUserOptLastKeyPair)
  FORWARD_CALL0(findTrustchainLastIndex)
  FORWARD_CALL0(findTrustchainPublicSignatureKey)
  FORWARD_CALL1(setTrustchainLastIndex)
  FORWARD_CALL1(setTrustchainPublicSignatureKey)
  FORWARD_CALL1(addTrustchainEntry)
  FORWARD_CALL1(findTrustchainEntry)
  FORWARD_CALL2(putContact)
  FORWARD_CALL1(findContactUserKey)
  FORWARD_CALL1(findContactUserIdByPublicEncryptionKey)
  FORWARD_CALL2(setContactPublicEncryptionKey)
  FORWARD_CALL1(putKeyPublishes)
  FORWARD_CALL1(findKeyPublish)
  FORWARD_CALL2(putResourceKey)
  FORWARD_CALL1(findResourceKey)
  FORWARD_CALL0(getDeviceKeys)
  FORWARD_CALL0(getDeviceId)
  FORWARD_CALL1(setDeviceKeys)
  FORWARD_CALL1(setDeviceId)
  FORWARD_CALL2(putDevice)
  FORWARD_CALL1(findDevice)
  FORWARD_CALL1(findDeviceUserId)
  FORWARD_CALL1(getDevicesOf)
  FORWARD_CALL2(updateDeviceRevokedAt)
  FORWARD_CALL1(putInternalGroup)
  FORWARD_CALL1(putExternalGroup)
  FORWARD_CALL2(putGroupProvisionalEncryptionKeys)
  FORWARD_CALL3(updateLastGroupBlock)
  FORWARD_CALL1(findInternalGroupByGroupId)
  FORWARD_CALL1(findExternalGroupByGroupId)
  FORWARD_CALL2(findExternalGroupsByProvisionalUser)
  FORWARD_CALL1(findInternalGroupByGroupPublicEncryptionKey)
  FORWARD_CALL1(findExternalGroupByGroupPublicEncryptionKey)
  FORWARD_CALL1(putProvisionalUserKeys)
  FORWARD_CALL2(findProvisionalUserKeys)
  FORWARD_CALL1(findProvisionalUserKeysByAppPublicEncryptionKey)
  FORWARD_CALL0(nuke)
  FORWARD_CALL0(startTransaction)
  FORWARD_CALL0(commitTransaction)
  FORWARD_CALL0(rollbackTransaction)

#undef FORWARD_CALL0
#undef FORWARD_CALL1
#undef FORWARD_CALL2
#undef FORWARD_CALL3
};

std::function<tc::cotask<std::unique_ptr<JsDatabaseInterface>>(
    std::string const& dbName)>
    jsDatabaseFactory;

void setJsDatabaseFactory(emscripten::val factory)
{
  jsDatabaseFactory = [=](std::string const& dbName) mutable
      -> tc::cotask<std::unique_ptr<JsDatabaseInterface>> {
    TC_RETURN(TC_AWAIT(jsPromiseToFuture(factory(dbName)))
                  .as<std::unique_ptr<JsDatabaseInterface>>());
  };
}
}

JsDatabase::JsDatabase()
{
}

JsDatabase::~JsDatabase() = default;

tc::cotask<void> JsDatabase::open(std::string const& dbName)
{
  _db = TC_AWAIT(jsDatabaseFactory(dbName));
}

tc::cotask<void> JsDatabase::putUserPrivateKey(
    Crypto::PublicEncryptionKey const& publicKey,
    Crypto::PrivateEncryptionKey const& privateKey)
{
  TC_AWAIT(jsPromiseToFuture(_db->putUserPrivateKey(
      containerToJs(publicKey), containerToJs(privateKey))));
  TC_RETURN();
}

tc::cotask<Crypto::EncryptionKeyPair> JsDatabase::getUserKeyPair(
    Crypto::PublicEncryptionKey const& publicKey)
{
  auto const keys = TC_AWAIT(
      jsPromiseToFuture(_db->getUserKeyPair(containerToJs(publicKey))));
  if (keys.isNull() || keys.isUndefined())
    throw DataStore::RecordNotFound("user key not found");
  TC_RETURN((Crypto::EncryptionKeyPair{
      Crypto::PublicEncryptionKey{copyToVector(keys[0])},
      Crypto::PrivateEncryptionKey{copyToVector(keys[1])}}));
}

tc::cotask<std::optional<Crypto::EncryptionKeyPair>>
JsDatabase::getUserOptLastKeyPair()
{
  auto const keys = TC_AWAIT(jsPromiseToFuture(_db->getUserOptLastKeyPair()));
  if (keys.isNull() || keys.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN((Crypto::EncryptionKeyPair{
      Crypto::PublicEncryptionKey{copyToVector(keys[0])},
      Crypto::PrivateEncryptionKey{copyToVector(keys[1])}}));
}

tc::cotask<std::optional<uint64_t>> JsDatabase::findTrustchainLastIndex()
{
  auto const optIndex =
      TC_AWAIT(jsPromiseToFuture(_db->findTrustchainLastIndex()));

  if (optIndex.isNull() || optIndex.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN(static_cast<uint64_t>(optIndex.as<double>()));
}

tc::cotask<std::optional<Crypto::PublicSignatureKey>>
JsDatabase::findTrustchainPublicSignatureKey()
{
  auto const optSignatureKey =
      TC_AWAIT(jsPromiseToFuture(_db->findTrustchainPublicSignatureKey()));

  if (optSignatureKey.isNull() || optSignatureKey.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN(Crypto::PublicSignatureKey{copyToVector(optSignatureKey)});
}

tc::cotask<void> JsDatabase::setTrustchainLastIndex(uint64_t idx)
{
  TC_AWAIT(jsPromiseToFuture(
      _db->setTrustchainLastIndex(emscripten::val{static_cast<double>(idx)})));
}

tc::cotask<void> JsDatabase::setTrustchainPublicSignatureKey(
    Crypto::PublicSignatureKey const& key)
{
  TC_AWAIT(jsPromiseToFuture(
      _db->setTrustchainLastIndex(emscripten::val{containerToJs(key)})));
}

namespace
{
struct toVal
{
  emscripten::val operator()(TrustchainCreation const& tc)
  {
    auto ret = emscripten::val::object();
    ret.set("publicSignatureKey", containerToJs(tc.publicSignatureKey()));
    return ret;
  }
  emscripten::val operator()(DeviceCreation const& dc)
  {
    auto ret = emscripten::val::object();
    ret.set("ephemeralPublicSignatureKey",
            containerToJs(dc.ephemeralPublicSignatureKey()));
    ret.set("userId", containerToJs(dc.userId()));
    ret.set("delegationSignature", containerToJs(dc.delegationSignature()));
    ret.set("publicSignatureKey", containerToJs(dc.publicSignatureKey()));
    ret.set("publicEncryptionKey", containerToJs(dc.publicEncryptionKey()));
    if (auto const dc3 = dc.get_if<DeviceCreation::v3>())
    {
      ret.set("userKeyPair", emscripten::val::object());
      ret["userKeyPair"].set("publicEncryptionKey",
                             containerToJs(dc3->publicUserEncryptionKey()));
      ret["userKeyPair"].set(
          "encryptedPrivateEncryptionKey",
          containerToJs(dc3->sealedPrivateUserEncryptionKey()));
      ret.set("isGhostDevice", emscripten::val(dc3->isGhostDevice()));
    }
    return ret;
  }

  emscripten::val operator()(KeyPublish const& kp)
  {
    return kp.visit([this](auto const& val) { return (*this)(val); });
  }

  emscripten::val operator()(KeyPublishToDevice const& kp)
  {
    auto ret = emscripten::val::object();
    ret.set("recipient", containerToJs(kp.recipient()));
    ret.set("resourceId", containerToJs(kp.resourceId()));
    ret.set("resourceKey", containerToJs(kp.encryptedSymmetricKey()));
    return ret;
  }
  emscripten::val operator()(DeviceRevocation const& tc)
  {
    // TODO
    return emscripten::val::object();
  }
  emscripten::val operator()(KeyPublishToUser const& kp)
  {
    auto ret = emscripten::val::object();
    ret.set("recipientPublicEncryptionKey",
            containerToJs(kp.recipientPublicEncryptionKey()));
    ret.set("resourceId", containerToJs(kp.resourceId()));
    ret.set("resourceKey", containerToJs(kp.sealedSymmetricKey()));
    return ret;
  }
  emscripten::val operator()(UserGroupCreation const& tc)
  {
    // TODO
    return emscripten::val::object();
  }
  emscripten::val operator()(KeyPublishToUserGroup const& tc)
  {
    auto ret = emscripten::val::object();
    ret.set("recipientPublicEncryptionKey",
            containerToJs(tc.recipientPublicEncryptionKey()));
    ret.set("resourceId", containerToJs(tc.resourceId()));
    ret.set("resourceKey", containerToJs(tc.sealedSymmetricKey()));
    return ret;
  }
  emscripten::val operator()(UserGroupAddition const& tc)
  {
    // TODO
    return emscripten::val::object();
  }
  emscripten::val operator()(KeyPublishToProvisionalUser const& kp)
  {
    auto ret = emscripten::val::object();
    ret.set("appPublicSignatureKey", containerToJs(kp.appPublicSignatureKey()));
    ret.set("tankerPublicSignatureKey",
            containerToJs(kp.tankerPublicSignatureKey()));
    ret.set("resourceId", containerToJs(kp.resourceId()));
    ret.set("resourceKey", containerToJs(kp.twoTimesSealedSymmetricKey()));
    return ret;
  }
  emscripten::val operator()(ProvisionalIdentityClaim const& tc)
  {
    // TODO
    return emscripten::val::object();
  }
};
}

tc::cotask<void> JsDatabase::addTrustchainEntry(Entry const& entry)
{
  auto val = emscripten::val::object();
  val.set("index", emscripten::val(static_cast<double>(entry.index)));
  val.set("nature", emscripten::val(static_cast<int>(entry.nature)));
  val.set("author", emscripten::val(containerToJs(entry.author)));
  val.set("action", entry.action.visit(toVal{}));
  val.set("hash", emscripten::val(containerToJs(entry.hash)));
  TC_AWAIT(jsPromiseToFuture(_db->addTrustchainEntry(val)));
}

namespace
{
Entry jsEntryToEntry(emscripten::val const& jsEntry)
{
  Entry entry{};
  entry.index = static_cast<uint64_t>(jsEntry["index"].as<double>());
  entry.nature = static_cast<Nature>(jsEntry["nature"].as<int>());
  entry.author = Crypto::Hash{copyToVector(jsEntry["author"])};
  entry.hash = Crypto::Hash{copyToVector(jsEntry["hash"])};

  if (entry.nature == Nature::TrustchainCreation)
  {
    entry.action = TrustchainCreation{Crypto::PublicSignatureKey{
        copyToVector(jsEntry["action"]["publicSignatureKey"])}};
  }
  else if (entry.nature == Nature::DeviceCreation ||
           entry.nature == Nature::DeviceCreation2 ||
           entry.nature == Nature::DeviceCreation3)
  {
    Crypto::PublicSignatureKey ephemeralPublicSignatureKey(
        copyToVector(jsEntry["action"]["ephemeralPublicSignatureKey"]));
    UserId userId(copyToVector(jsEntry["action"]["userId"]));
    Crypto::Signature delegationSignature(
        copyToVector(jsEntry["action"]["delegationSignature"]));
    Crypto::PublicSignatureKey publicSignatureKey(
        copyToVector(jsEntry["action"]["publicSignatureKey"]));
    Crypto::PublicEncryptionKey publicEncryptionKey(
        copyToVector(jsEntry["action"]["publicEncryptionKey"]));

    if (!jsEntry["action"]["userKeyPair"].isNull() &&
        !jsEntry["action"]["userKeyPair"].isUndefined())
    {
      Crypto::PublicEncryptionKey publicUserEncryptionKey(copyToVector(
          jsEntry["action"]["userKeyPair"]["publicEncryptionKey"]));
      Crypto::SealedPrivateEncryptionKey sealedPrivateEncryptionKey(
          copyToVector(jsEntry["action"]["userKeyPair"]
                              ["encryptedPrivateEncryptionKey"]));
      auto isGhostDevice = jsEntry["action"]["isGhostDevice"].as<bool>();

      DeviceCreation::v3 dc(
          ephemeralPublicSignatureKey,
          userId,
          delegationSignature,
          publicSignatureKey,
          publicEncryptionKey,
          publicUserEncryptionKey,
          sealedPrivateEncryptionKey,
          (isGhostDevice ? DeviceCreation::DeviceType::GhostDevice :
                           DeviceCreation::DeviceType::Device));
      entry.action = dc;
    }
    else
    {
      DeviceCreation::v1 dc(ephemeralPublicSignatureKey,
                            userId,
                            delegationSignature,
                            publicSignatureKey,
                            publicEncryptionKey);
      entry.action = dc;
    }
  }
  else if (entry.nature == Nature::KeyPublishToDevice)
  {
    KeyPublishToDevice kp(
        DeviceId{copyToVector(jsEntry["action"]["recipient"])},
        ResourceId{copyToVector(jsEntry["action"]["resourceId"])},
        Crypto::EncryptedSymmetricKey{
            copyToVector(jsEntry["action"]["resourceKey"])});
    entry.action = kp;
  }
  else if (entry.nature == Nature::KeyPublishToUser)
  {
    Crypto::PublicEncryptionKey const recipientPublicEncryptionKey(
        copyToVector(jsEntry["action"]["recipientPublicEncryptionKey"]));
    ResourceId const resourceId(copyToVector(jsEntry["action"]["resourceId"]));
    Crypto::SealedSymmetricKey const sealedSymmetricKey(
        copyToVector(jsEntry["action"]["resourceKey"]));
    entry.action = KeyPublishToUser{
        recipientPublicEncryptionKey, resourceId, sealedSymmetricKey};
  }
  else if (entry.nature == Nature::KeyPublishToUserGroup)
  {
    Crypto::PublicEncryptionKey const recipientPublicEncryptionKey(
        copyToVector(jsEntry["action"]["recipientPublicEncryptionKey"]));
    ResourceId const resourceId(copyToVector(jsEntry["action"]["resourceId"]));
    Crypto::SealedSymmetricKey const sealedSymmetricKey(
        copyToVector(jsEntry["action"]["resourceKey"]));
    entry.action = KeyPublishToUserGroup{
        recipientPublicEncryptionKey, resourceId, sealedSymmetricKey};
  }
  else if (entry.nature == Nature::KeyPublishToProvisionalUser)
  {
    Crypto::PublicSignatureKey const appPublicSignatureKey{
        copyToVector(jsEntry["action"]["appPublicSignatureKey"])};
    Crypto::PublicSignatureKey const tankerPublicSignatureKey{
        copyToVector(jsEntry["action"]["tankerPublicSignatureKey"])};
    ResourceId const resourceId{copyToVector(jsEntry["action"]["resourceId"])};
    Crypto::TwoTimesSealedSymmetricKey const key{
        copyToVector(jsEntry["action"]["resourceKey"])};
    entry.action = KeyPublishToProvisionalUser{
        appPublicSignatureKey, resourceId, tankerPublicSignatureKey, key};
  }

  return entry;
}
}

tc::cotask<std::optional<Entry>> JsDatabase::findTrustchainEntry(
    Crypto::Hash const& hash)
{
  auto const entry = TC_AWAIT(
      jsPromiseToFuture(_db->findTrustchainEntry(containerToJs(hash))));
  if (entry.isNull() || entry.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN(jsEntryToEntry(entry));
}

tc::cotask<void> JsDatabase::putContact(
    UserId const& userId,
    std::optional<Crypto::PublicEncryptionKey> const& publicKey)
{
  TC_AWAIT(jsPromiseToFuture(_db->putContact(
      containerToJs(userId),
      publicKey ? containerToJs(*publicKey) : emscripten::val::null())));
}

tc::cotask<std::optional<Crypto::PublicEncryptionKey>>
JsDatabase::findContactUserKey(UserId const& userId)
{
  auto const key = TC_AWAIT(
      jsPromiseToFuture(_db->findContactUserKey(containerToJs(userId))));
  if (key.isNull() || key.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN(Crypto::PublicEncryptionKey(copyToVector(key)));
}

tc::cotask<std::optional<UserId>>
JsDatabase::findContactUserIdByPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& userPublicKey)
{
  auto const userId =
      TC_AWAIT(jsPromiseToFuture(_db->findContactUserIdByPublicEncryptionKey(
          containerToJs(userPublicKey))));
  if (userId.isNull() || userId.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN(UserId(copyToVector(userId)));
}

tc::cotask<void> JsDatabase::setContactPublicEncryptionKey(
    UserId const& userId, Crypto::PublicEncryptionKey const& userPublicKey)
{
  TC_AWAIT(jsPromiseToFuture(_db->setContactPublicEncryptionKey(
      containerToJs(userId), containerToJs(userPublicKey))));
}

namespace
{
emscripten::val toJsKeyPublish(KeyPublish const& kp)
{
  auto val = emscripten::val::object();
  val.set("resourceId", containerToJs(kp.resourceId()));
  val.set("nature", static_cast<int>(kp.nature()));
  if (auto const kp2 = kp.get_if<KeyPublishToDevice>())
  {
    val.set("recipient", containerToJs(kp2->recipient()));
    val.set("encryptedSymmetricKey",
            containerToJs(kp2->encryptedSymmetricKey()));
  }
  else if (auto const kp2 = kp.get_if<KeyPublishToUser>())
  {
    val.set("recipient", containerToJs(kp2->recipientPublicEncryptionKey()));
    val.set("encryptedSymmetricKey", containerToJs(kp2->sealedSymmetricKey()));
  }
  else if (auto const kp2 = kp.get_if<KeyPublishToUserGroup>())
  {
    val.set("recipient", containerToJs(kp2->recipientPublicEncryptionKey()));
    val.set("encryptedSymmetricKey", containerToJs(kp2->sealedSymmetricKey()));
  }
  else if (auto const kp2 = kp.get_if<KeyPublishToProvisionalUser>())
  {
    val.set("appSignaturePublicKey",
            containerToJs(kp2->appPublicSignatureKey()));
    val.set("tankerSignaturePublicKey",
            containerToJs(kp2->tankerPublicSignatureKey()));
    val.set("encryptedSymmetricKey",
            containerToJs(kp2->twoTimesSealedSymmetricKey()));
  }
  return val;
}

KeyPublish fromJsKeyPublish(emscripten::val const& jkp)
{
  auto const resourceId =
      Trustchain::ResourceId{copyToVector(jkp["resourceId"])};
  auto const encryptedSymmetricKey = copyToVector(jkp["encryptedSymmetricKey"]);
  auto const nature = static_cast<Nature>(jkp["nature"].as<int>());

  switch (nature)
  {
  case Nature::KeyPublishToDevice:
    return KeyPublishToDevice{
        Trustchain::DeviceId{copyToVector(jkp["recipient"])},
        resourceId,
        Crypto::EncryptedSymmetricKey{encryptedSymmetricKey},
    };
  case Nature::KeyPublishToUser:
    return KeyPublishToUser{
        Crypto::PublicEncryptionKey{copyToVector(jkp["recipient"])},
        resourceId,
        Crypto::SealedSymmetricKey{encryptedSymmetricKey},
    };
  case Nature::KeyPublishToUserGroup:
    return KeyPublishToUserGroup{
        Crypto::PublicEncryptionKey{copyToVector(jkp["recipient"])},
        resourceId,
        Crypto::SealedSymmetricKey{encryptedSymmetricKey},
    };
  case Nature::KeyPublishToProvisionalUser:
    return KeyPublishToProvisionalUser{
        Crypto::PublicSignatureKey{copyToVector(jkp["appSignaturePublicKey"])},
        resourceId,
        Crypto::PublicSignatureKey{
            copyToVector(jkp["tankerSignaturePublicKey"])},
        Crypto::TwoTimesSealedSymmetricKey{encryptedSymmetricKey},
    };
  default:
    throw Errors::formatEx(Errors::Errc::InternalError,
                           "invalid nature for key publish: {}",
                           nature);
  }
}
}

tc::cotask<void> JsDatabase::putKeyPublishes(gsl::span<KeyPublish const> kps)
{
  auto jkps = emscripten::val::array();
  for (auto const& kp : kps)
    jkps.call<void>("push", toJsKeyPublish(kp));
  TC_AWAIT(jsPromiseToFuture(_db->putKeyPublishes(jkps)));
}

tc::cotask<std::optional<KeyPublish>> JsDatabase::findKeyPublish(
    ResourceId const& resourceId)
{
  auto const optKp = TC_AWAIT(
      jsPromiseToFuture(_db->findKeyPublish(containerToJs(resourceId))));
  if (optKp.isNull() || optKp.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN(fromJsKeyPublish(optKp));
}

tc::cotask<void> JsDatabase::putResourceKey(ResourceId const& resourceId,
                                            Crypto::SymmetricKey const& key)
{
  TC_AWAIT(jsPromiseToFuture(
      _db->putResourceKey(containerToJs(resourceId), containerToJs(key))));
}

tc::cotask<std::optional<Crypto::SymmetricKey>> JsDatabase::findResourceKey(
    ResourceId const& resourceId)
{
  auto const key = TC_AWAIT(
      jsPromiseToFuture(_db->findResourceKey(containerToJs(resourceId))));
  if (key.isNull() || key.isUndefined())
    TC_RETURN(std::nullopt);
  TC_RETURN(Crypto::SymmetricKey(copyToVector(key)));
}

tc::cotask<std::optional<DeviceKeys>> JsDatabase::getDeviceKeys()
{
  auto const keys = TC_AWAIT(jsPromiseToFuture(_db->getDeviceKeys()));
  if (keys.isNull() || keys.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN((DeviceKeys{
      {Crypto::PublicSignatureKey(copyToVector(keys["publicSignatureKey"])),
       Crypto::PrivateSignatureKey(copyToVector(keys["privateSignatureKey"]))},
      {Crypto::PublicEncryptionKey(copyToVector(keys["publicEncryptionKey"])),
       Crypto::PrivateEncryptionKey(
           copyToVector(keys["privateEncryptionKey"]))}}));
}

tc::cotask<std::optional<Trustchain::DeviceId>> JsDatabase::getDeviceId()
{
  auto const deviceId = TC_AWAIT(jsPromiseToFuture(_db->getDeviceId()));
  if (deviceId.isNull() || deviceId.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN(DeviceId(copyToVector(deviceId)));
}

tc::cotask<void> JsDatabase::setDeviceKeys(DeviceKeys const& deviceKeys)
{
  auto jsDeviceKeys = emscripten::val::object();
  jsDeviceKeys.set("privateSignatureKey",
                   containerToJs(deviceKeys.signatureKeyPair.privateKey));
  jsDeviceKeys.set("publicSignatureKey",
                   containerToJs(deviceKeys.signatureKeyPair.publicKey));
  jsDeviceKeys.set("privateEncryptionKey",
                   containerToJs(deviceKeys.encryptionKeyPair.privateKey));
  jsDeviceKeys.set("publicEncryptionKey",
                   containerToJs(deviceKeys.encryptionKeyPair.publicKey));
  TC_AWAIT(jsPromiseToFuture(_db->setDeviceKeys(jsDeviceKeys)));
}

tc::cotask<void> JsDatabase::setDeviceId(DeviceId const& deviceId)
{
  TC_AWAIT(jsPromiseToFuture(_db->setDeviceId(containerToJs(deviceId))));
}

tc::cotask<void> JsDatabase::putDevice(UserId const& userId,
                                       Device const& device)
{
  auto jsdev = emscripten::val::object();
  jsdev.set("id", containerToJs(device.id));
  jsdev.set("createdAtBlkIndex", static_cast<double>(device.createdAtBlkIndex));
  jsdev.set(
      "revokedAtBlkIndex",
      device.revokedAtBlkIndex ?
          emscripten::val(static_cast<double>(*device.revokedAtBlkIndex)) :
          emscripten::val::null());
  jsdev.set("publicSignatureKey", containerToJs(device.publicSignatureKey));
  jsdev.set("publicEncryptionKey", containerToJs(device.publicEncryptionKey));
  jsdev.set("isGhostDevice", device.isGhostDevice);
  TC_AWAIT(jsPromiseToFuture(_db->putDevice(containerToJs(userId), jsdev)));
}

namespace
{
Device fromJsDevice(emscripten::val const& jsdev)
{
  auto const jsRevokedAt = jsdev["revokedAtBlkIndex"];
  return Device{
      DeviceId(copyToVector(jsdev["id"])),
      static_cast<uint64_t>(jsdev["createdAtBlkIndex"].as<double>()),
      jsRevokedAt.isNull() || jsRevokedAt.isUndefined() ?
          std::optional<uint64_t>{} :
          static_cast<uint64_t>(jsRevokedAt.as<double>()),
      Crypto::PublicSignatureKey(copyToVector(jsdev["publicSignatureKey"])),
      Crypto::PublicEncryptionKey(copyToVector(jsdev["publicEncryptionKey"])),
      jsdev["isGhostDevice"].as<bool>(),
  };
}
}

tc::cotask<std::optional<Device>> JsDatabase::findDevice(DeviceId const& id)
{
  auto const jsdev =
      TC_AWAIT(jsPromiseToFuture(_db->findDevice(containerToJs(id))));
  if (jsdev.isNull() || jsdev.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN(fromJsDevice(jsdev));
}

tc::cotask<std::optional<UserId>> JsDatabase::findDeviceUserId(
    DeviceId const& id)
{
  auto const jsdev =
      TC_AWAIT(jsPromiseToFuture(_db->findDeviceUserId(containerToJs(id))));
  if (jsdev.isNull() || jsdev.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN(UserId{copyToVector(jsdev)});
}

tc::cotask<void> JsDatabase::updateDeviceRevokedAt(DeviceId const& id,
                                                   uint64_t revokedAtBlkIndex)
{
  TC_AWAIT(jsPromiseToFuture(_db->updateDeviceRevokedAt(
      containerToJs(id),
      emscripten::val(static_cast<double>(revokedAtBlkIndex)))));
}

tc::cotask<std::vector<Device>> JsDatabase::getDevicesOf(UserId const& id)
{
  auto const jsdevs =
      TC_AWAIT(jsPromiseToFuture(_db->getDevicesOf(containerToJs(id))));

  auto const size = jsdevs["length"].as<size_t>();
  std::vector<Device> out;
  out.reserve(size);
  for (size_t i = 0; i < size; ++i)
    out.push_back(fromJsDevice(jsdevs[i]));
  TC_RETURN(out);
}

tc::cotask<void> JsDatabase::putInternalGroup(InternalGroup const& group)
{
  auto jsgroup = emscripten::val::object();
  jsgroup.set("id", containerToJs(group.id));
  jsgroup.set("publicSignatureKey",
              containerToJs(group.signatureKeyPair.publicKey));
  jsgroup.set("privateSignatureKey",
              containerToJs(group.signatureKeyPair.privateKey));
  jsgroup.set("publicEncryptionKey",
              containerToJs(group.encryptionKeyPair.publicKey));
  jsgroup.set("privateEncryptionKey",
              containerToJs(group.encryptionKeyPair.privateKey));
  jsgroup.set("lastBlockHash", containerToJs(group.lastBlockHash));
  jsgroup.set("lastBlockIndex", static_cast<double>(group.lastBlockIndex));
  TC_AWAIT(jsPromiseToFuture(_db->putInternalGroup(jsgroup)));
}

tc::cotask<void> JsDatabase::putExternalGroup(ExternalGroup const& group)
{
  auto jsgroup = emscripten::val::object();
  jsgroup.set("id", containerToJs(group.id));
  jsgroup.set("publicSignatureKey", containerToJs(group.publicSignatureKey));
  jsgroup.set("encryptedPrivateSignatureKey",
              group.encryptedPrivateSignatureKey ?
                  containerToJs(*group.encryptedPrivateSignatureKey) :
                  emscripten::val::null());
  jsgroup.set("publicEncryptionKey", containerToJs(group.publicEncryptionKey));
  jsgroup.set("lastBlockHash", containerToJs(group.lastBlockHash));
  jsgroup.set("lastBlockIndex", static_cast<double>(group.lastBlockIndex));

  auto jsprovisionalUsers = emscripten::val::array();
  for (auto const& provisionalUser : group.provisionalUsers)
  {
    auto jsprovisionalUser = emscripten::val::object();
    jsprovisionalUser.set(
        "appSignaturePublicKey",
        containerToJs(provisionalUser.appPublicSignatureKey()));
    jsprovisionalUser.set(
        "tankerSignaturePublicKey",
        containerToJs(provisionalUser.tankerPublicSignatureKey()));
    jsprovisionalUser.set(
        "encryptedPrivateEncryptionKey",
        containerToJs(provisionalUser.encryptedPrivateEncryptionKey()));
    jsprovisionalUsers.call<void>("push", jsprovisionalUser);
  }
  jsgroup.set("provisionalMembers", jsprovisionalUsers);

  TC_AWAIT(jsPromiseToFuture(_db->putExternalGroup(jsgroup)));
}

tc::cotask<void> JsDatabase::putGroupProvisionalEncryptionKeys(
    Trustchain::GroupId const& groupId,
    std::vector<GroupProvisionalUser> const& provisionalUsers)
{
  auto jsprovisionalUsers = emscripten::val::array();
  for (auto const& provisionalUser : provisionalUsers)
  {
    auto jsprovisionalUser = emscripten::val::object();
    jsprovisionalUser.set(
        "appSignaturePublicKey",
        containerToJs(provisionalUser.appPublicSignatureKey()));
    jsprovisionalUser.set(
        "tankerSignaturePublicKey",
        containerToJs(provisionalUser.tankerPublicSignatureKey()));
    jsprovisionalUser.set(
        "encryptedPrivateEncryptionKey",
        containerToJs(provisionalUser.encryptedPrivateEncryptionKey()));
    jsprovisionalUsers.call<void>("push", jsprovisionalUser);
  }
  TC_AWAIT(jsPromiseToFuture(_db->putGroupProvisionalEncryptionKeys(
      containerToJs(groupId), jsprovisionalUsers)));
}

tc::cotask<void> JsDatabase::updateLastGroupBlock(
    GroupId const& groupId,
    Crypto::Hash const& lastBlockHash,
    uint64_t lastBlockIndex)
{
  TC_AWAIT(jsPromiseToFuture(_db->updateLastGroupBlock(
      containerToJs(groupId),
      containerToJs(lastBlockHash),
      emscripten::val(static_cast<double>(lastBlockIndex)))));
}

namespace
{
InternalGroup fromJsInternalGroup(emscripten::val const& group)
{
  return InternalGroup{
      GroupId(copyToVector(group["id"])),
      {Crypto::PublicSignatureKey(copyToVector(group["publicSignatureKey"])),
       Crypto::PrivateSignatureKey(copyToVector(group["privateSignatureKey"]))},
      {Crypto::PublicEncryptionKey(copyToVector(group["publicEncryptionKey"])),
       Crypto::PrivateEncryptionKey(
           copyToVector(group["privateEncryptionKey"]))},
      Crypto::Hash(copyToVector(group["lastBlockHash"])),
      static_cast<uint64_t>(group["lastBlockIndex"].as<double>()),
  };
}

ExternalGroup fromJsExternalGroup(emscripten::val const& group)
{
  auto const encryptedPrivateSignatureKey =
      group["encryptedPrivateSignatureKey"];
  std::vector<GroupProvisionalUser> provisionalMembers;
  auto const jsprovisionalMembers = group["provisionalMembers"];
  auto const provisionalMembersLen =
      optionalFromValue<int>(jsprovisionalMembers, "length").value_or(0);
  for (int i = 0; i < provisionalMembersLen; ++i)
    provisionalMembers.push_back(GroupProvisionalUser{
        Crypto::PublicSignatureKey(
            copyToVector(jsprovisionalMembers[i]["appSignaturePublicKey"])),
        Crypto::PublicSignatureKey(
            copyToVector(jsprovisionalMembers[i]["tankerSignaturePublicKey"])),
        Crypto::TwoTimesSealedPrivateEncryptionKey(copyToVector(
            jsprovisionalMembers[i]["encryptedPrivateEncryptionKey"])),
    });
  return ExternalGroup{
      GroupId(copyToVector(group["id"])),
      Crypto::PublicSignatureKey(copyToVector(group["publicSignatureKey"])),
      encryptedPrivateSignatureKey.isNull() ||
              encryptedPrivateSignatureKey.isUndefined() ?
          std::optional<Crypto::SealedPrivateSignatureKey>{} :
          Crypto::SealedPrivateSignatureKey(
              copyToVector(encryptedPrivateSignatureKey)),
      Crypto::PublicEncryptionKey(copyToVector(group["publicEncryptionKey"])),
      Crypto::Hash(copyToVector(group["lastBlockHash"])),
      static_cast<uint64_t>(group["lastBlockIndex"].as<double>()),
      provisionalMembers,
  };
}
}

tc::cotask<std::optional<InternalGroup>> JsDatabase::findInternalGroupByGroupId(
    GroupId const& id)
{
  auto const jsgroup = TC_AWAIT(
      jsPromiseToFuture(_db->findInternalGroupByGroupId(containerToJs(id))));
  if (jsgroup.isNull() || jsgroup.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN(fromJsInternalGroup(jsgroup));
}

tc::cotask<std::optional<ExternalGroup>>
JsDatabase::findExternalGroupByGroupId(GroupId const& id)
{
  auto const jsgroup = TC_AWAIT(
      jsPromiseToFuture(_db->findExternalGroupByGroupId(containerToJs(id))));
  if (jsgroup.isNull() || jsgroup.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN(fromJsExternalGroup(jsgroup));
}

tc::cotask<std::vector<ExternalGroup>>
JsDatabase::findExternalGroupsByProvisionalUser(
    Crypto::PublicSignatureKey const& appPublicSignatureKey,
    Crypto::PublicSignatureKey const& tankerPublicSignatureKey)
{
  auto const jsgroups =
      TC_AWAIT(jsPromiseToFuture(_db->findExternalGroupsByProvisionalUser(
          containerToJs(appPublicSignatureKey),
          containerToJs(tankerPublicSignatureKey))));

  std::vector<ExternalGroup> out;
  auto const nbGroups = jsgroups["length"].as<int>();
  for (int i = 0; i < nbGroups; ++i)
    out.push_back(fromJsExternalGroup(jsgroups[i]));
  TC_RETURN(out);
}

tc::cotask<std::optional<InternalGroup>>
JsDatabase::findInternalGroupByGroupPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey)
{
  auto const jsgroup =
      TC_AWAIT(jsPromiseToFuture(_db->findInternalGroupByGroupPublicEncryptionKey(
          containerToJs(publicEncryptionKey))));
  if (jsgroup.isNull() || jsgroup.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN(fromJsInternalGroup(jsgroup));
}

namespace
{
ProvisionalUserKeys fromJsProvisionalUserKeys(emscripten::val const& keys)
{
  return ProvisionalUserKeys{
      {Crypto::PublicEncryptionKey(
           copyToVector(keys["provisionalUserKeys"]["appPublicEncryptionKey"])),
       Crypto::PrivateEncryptionKey(copyToVector(
           keys["provisionalUserKeys"]["appPrivateEncryptionKey"]))},
      {Crypto::PublicEncryptionKey(copyToVector(
           keys["provisionalUserKeys"]["tankerPublicEncryptionKey"])),
       Crypto::PrivateEncryptionKey(copyToVector(
           keys["provisionalUserKeys"]["tankerPrivateEncryptionKey"]))}};
}
}

tc::cotask<std::optional<ExternalGroup>>
JsDatabase::findExternalGroupByGroupPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey)
{
  auto const jsgroup = TC_AWAIT(
      jsPromiseToFuture(_db->findExternalGroupByGroupPublicEncryptionKey(
          containerToJs(publicEncryptionKey))));
  if (jsgroup.isNull() || jsgroup.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN(fromJsExternalGroup(jsgroup));
}

tc::cotask<void> JsDatabase::putProvisionalUserKeys(
    Crypto::PublicSignatureKey const& appPublicSigKey,
    Crypto::PublicSignatureKey const& tankerPublicSigKey,
    ProvisionalUserKeys const& provisionalUserKeys)
{
  auto jskeys = emscripten::val::object();
  jskeys.set("appPublicSignatureKey", containerToJs(appPublicSigKey));
  jskeys.set("tankerPublicSignatureKey", containerToJs(tankerPublicSigKey));

  auto provisional = emscripten::val::object();
  provisional.set("appPublicEncryptionKey",
                  containerToJs(provisionalUserKeys.appKeys.publicKey));
  provisional.set("appPrivateEncryptionKey",
                  containerToJs(provisionalUserKeys.appKeys.privateKey));
  provisional.set("tankerPublicEncryptionKey",
                  containerToJs(provisionalUserKeys.tankerKeys.publicKey));
  provisional.set("tankerPrivateEncryptionKey",
                  containerToJs(provisionalUserKeys.tankerKeys.privateKey));
  jskeys.set("provisionalUserKeys", provisional);

  TC_AWAIT(jsPromiseToFuture(_db->putProvisionalUserKeys(jskeys)));
}

tc::cotask<std::optional<ProvisionalUserKeys>>
JsDatabase::findProvisionalUserKeys(
    Crypto::PublicSignatureKey const& appPublicSigKey,
    Crypto::PublicSignatureKey const& tankerPublicSigKey)
{
  auto const jskeys = TC_AWAIT(jsPromiseToFuture(_db->findProvisionalUserKeys(
      containerToJs(appPublicSigKey), containerToJs(tankerPublicSigKey))));
  if (jskeys.isNull() || jskeys.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN(fromJsProvisionalUserKeys(jskeys));
}

tc::cotask<std::optional<ProvisionalUserKeys>>
JsDatabase::findProvisionalUserKeysByAppPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& appPublicEncKey)
{
  auto const jskeys = TC_AWAIT(
      jsPromiseToFuture(_db->findProvisionalUserKeysByAppPublicEncryptionKey(
          containerToJs(appPublicEncKey))));
  if (jskeys.isNull() || jskeys.isUndefined())
    TC_RETURN(std::nullopt);

  TC_RETURN(fromJsProvisionalUserKeys(jskeys));
}

tc::cotask<void> JsDatabase::nuke()
{
  TC_AWAIT(jsPromiseToFuture(_db->nuke()));
}

tc::cotask<void> JsDatabase::startTransaction()
{
  TC_AWAIT(jsPromiseToFuture(_db->startTransaction()));
}
tc::cotask<void> JsDatabase::commitTransaction()
{
  TC_AWAIT(jsPromiseToFuture(_db->commitTransaction()));
}
tc::cotask<void> JsDatabase::rollbackTransaction()
{
  TC_AWAIT(jsPromiseToFuture(_db->rollbackTransaction()));
}
}
}

EMSCRIPTEN_BINDINGS(jsdatabaseinterface)
{
  using namespace Tanker::DataStore;

  emscripten::class_<JsDatabaseInterface>("JsDatabaseInterface")
      .function("putUserPrivateKey",
                &JsDatabaseInterface::putUserPrivateKey,
                emscripten::pure_virtual())
      .function("getUserKeyPair",
                &JsDatabaseInterface::getUserKeyPair,
                emscripten::pure_virtual())
      .function("getUserOptLastKeyPair",
                &JsDatabaseInterface::getUserOptLastKeyPair,
                emscripten::pure_virtual())
      .function("findTrustchainLastIndex",
                &JsDatabaseInterface::findTrustchainLastIndex,
                emscripten::pure_virtual())
      .function("findTrustchainPublicSignatureKey",
                &JsDatabaseInterface::findTrustchainPublicSignatureKey,
                emscripten::pure_virtual())
      .function("setTrustchainLastIndex",
                &JsDatabaseInterface::setTrustchainLastIndex,
                emscripten::pure_virtual())
      .function("setTrustchainPublicSignatureKey",
                &JsDatabaseInterface::setTrustchainPublicSignatureKey,
                emscripten::pure_virtual())
      .function("addTrustchainEntry",
                &JsDatabaseInterface::addTrustchainEntry,
                emscripten::pure_virtual())
      .function("findTrustchainEntry",
                &JsDatabaseInterface::findTrustchainEntry,
                emscripten::pure_virtual())
      .function("putContact",
                &JsDatabaseInterface::putContact,
                emscripten::pure_virtual())
      .function("findContactUserKey",
                &JsDatabaseInterface::findContactUserKey,
                emscripten::pure_virtual())
      .function("findContactUserIdByPublicEncryptionKey",
                &JsDatabaseInterface::findContactUserIdByPublicEncryptionKey,
                emscripten::pure_virtual())
      .function("setContactPublicEncryptionKey",
                &JsDatabaseInterface::setContactPublicEncryptionKey,
                emscripten::pure_virtual())
      .function("putKeyPublishes",
                &JsDatabaseInterface::putKeyPublishes,
                emscripten::pure_virtual())
      .function("findKeyPublish",
                &JsDatabaseInterface::findKeyPublish,
                emscripten::pure_virtual())
      .function("putResourceKey",
                &JsDatabaseInterface::putResourceKey,
                emscripten::pure_virtual())
      .function("findResourceKey",
                &JsDatabaseInterface::findResourceKey,
                emscripten::pure_virtual())
      .function("getDeviceKeys",
                &JsDatabaseInterface::getDeviceKeys,
                emscripten::pure_virtual())
      .function("getDeviceId",
                &JsDatabaseInterface::getDeviceId,
                emscripten::pure_virtual())
      .function("setDeviceKeys",
                &JsDatabaseInterface::setDeviceKeys,
                emscripten::pure_virtual())
      .function("setDeviceId",
                &JsDatabaseInterface::setDeviceId,
                emscripten::pure_virtual())
      .function("putDevice",
                &JsDatabaseInterface::putDevice,
                emscripten::pure_virtual())
      .function("findDevice",
                &JsDatabaseInterface::findDevice,
                emscripten::pure_virtual())
      .function("getDevicesOf",
                &JsDatabaseInterface::getDevicesOf,
                emscripten::pure_virtual())
      .function("findDeviceUserId",
                &JsDatabaseInterface::findDeviceUserId,
                emscripten::pure_virtual())
      .function("updateDeviceRevokedAt",
                &JsDatabaseInterface::updateDeviceRevokedAt,
                emscripten::pure_virtual())
      .function("putInternalGroup",
                &JsDatabaseInterface::putInternalGroup,
                emscripten::pure_virtual())
      .function("putExternalGroup",
                &JsDatabaseInterface::putExternalGroup,
                emscripten::pure_virtual())
      .function("updateLastGroupBlock",
                &JsDatabaseInterface::updateLastGroupBlock,
                emscripten::pure_virtual())
      .function("findInternalGroupByGroupId",
                &JsDatabaseInterface::findInternalGroupByGroupId,
                emscripten::pure_virtual())
      .function("findExternalGroupByGroupId",
                &JsDatabaseInterface::findExternalGroupByGroupId,
                emscripten::pure_virtual())
      .function("findInternalGroupByGroupPublicEncryptionKey",
                &JsDatabaseInterface::findInternalGroupByGroupPublicEncryptionKey,
                emscripten::pure_virtual())
      .function(
          "findExternalGroupByGroupPublicEncryptionKey",
          &JsDatabaseInterface::findExternalGroupByGroupPublicEncryptionKey,
          emscripten::pure_virtual())
      .function("putProvisionalUserKeys",
                &JsDatabaseInterface::putProvisionalUserKeys,
                emscripten::pure_virtual())
      .function("findProvisionalUserKeys",
                &JsDatabaseInterface::findProvisionalUserKeys,
                emscripten::pure_virtual())
      .function(
          "findProvisionalUserKeysByAppPublicEncryptionKey",
          &JsDatabaseInterface::findProvisionalUserKeysByAppPublicEncryptionKey,
          emscripten::pure_virtual())
      .function("nuke", &JsDatabaseInterface::nuke, emscripten::pure_virtual())
      .function("startTransaction",
                &JsDatabaseInterface::startTransaction,
                emscripten::pure_virtual())
      .function("commitTransaction",
                &JsDatabaseInterface::commitTransaction,
                emscripten::pure_virtual())
      .function("rollbackTransaction",
                &JsDatabaseInterface::rollbackTransaction,
                emscripten::pure_virtual())
      .allow_subclass<JsDatabaseInterfaceWrapper>("JsDatabaseInterfaceWrapper");

  emscripten::function("setJsDatabaseFactory",
                       &Tanker::DataStore::setJsDatabaseFactory);
}
