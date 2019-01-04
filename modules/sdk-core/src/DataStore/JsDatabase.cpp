#include <Tanker/Crypto/KeyFormat.hpp>
#include <Tanker/DataStore/JsDatabase.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Log.hpp>

#include <emscripten.h>
#include <emscripten/bind.h>

TLOG_CATEGORY(Database);

namespace Tanker
{
namespace DataStore
{
namespace
{
template <typename T>
emscripten::val vectorToJs(T const& vec)
{
  using emscripten::val;

  auto const Uint8Array = val::global("Uint8Array");
  val memory = val::module_property("buffer");
  return Uint8Array.new_(
      memory, reinterpret_cast<uintptr_t>(vec.data()), vec.size());
}
std::vector<uint8_t> copyToVector(const emscripten::val& typedArray)
{
  using emscripten::val;

  unsigned int length = typedArray["length"].as<unsigned int>();
  std::vector<uint8_t> vec(length);

  val memory = val::module_property("buffer");
  val memoryView = typedArray["constructor"].new_(
      memory, reinterpret_cast<uintptr_t>(vec.data()), length);

  memoryView.call<void>("set", typedArray);

  return vec;
}

template <typename Sig>
emscripten::val toJsFunctor(std::function<Sig> functor)
{
  return emscripten::val(functor)["opcall"].template call<emscripten::val>(
      "bind", emscripten::val(functor));
}

tc::cotask<emscripten::val> jsPromiseToFuture(emscripten::val const& jspromise)
{
  tc::promise<emscripten::val> cpppromise;
  auto const thenCb = std::function<void(emscripten::val const& val)>(
      [=](emscripten::val const& value) mutable {
        cpppromise.set_value(value);
      });
  auto const catchCb = std::function<void(emscripten::val const&)>(
      [=](emscripten::val const& error) mutable {
        cpppromise.set_exception(
            std::make_exception_ptr(Error::formatEx<std::runtime_error>(
                "some error happened, deal with it: {}",
                error.isNull() ? "null" :
                                 error.isUndefined() ?
                                 "undefined" :
                                 error.call<std::string>("toString") + "\n" +
                                         error["stack"].as<std::string>())));
      });
  jspromise.call<emscripten::val>("then", toJsFunctor(thenCb))
      .call<emscripten::val>("catch", toJsFunctor(catchCb));
  TC_RETURN(TC_AWAIT(cpppromise.get_future()));
}
}

class JsDatabaseInterface
{
public:
  virtual ~JsDatabaseInterface() = default;
  virtual emscripten::val putUserPrivateKey(
      emscripten::val const& publicKey, emscripten::val const& privateKey) = 0;
  virtual emscripten::val getUserKeyPair(emscripten::val const& publicKey) = 0;
  virtual emscripten::val getUserOptLastKeyPair() = 0;

  virtual emscripten::val getTrustchainLastIndex() = 0;
  virtual emscripten::val addTrustchainEntry(emscripten::val const& entry) = 0;
  virtual emscripten::val findTrustchainEntry(
      emscripten::val const& resourceId) = 0;
  virtual emscripten::val findTrustchainKeyPublish(
      emscripten::val const& resourceId) = 0;
  virtual emscripten::val getTrustchainDevicesOf(
      emscripten::val const& userId) = 0;
  virtual emscripten::val getTrustchainDevice(
      emscripten::val const& deviceId) = 0;

  virtual emscripten::val putContact(emscripten::val const& userId,
                                     emscripten::val const& publicKey) = 0;
  virtual emscripten::val findContactUserKey(emscripten::val const& userId) = 0;
  virtual emscripten::val findContactUserIdByPublicEncryptionKey(
      emscripten::val const& publicEncryptionKey) = 0;
  virtual emscripten::val setContactPublicEncryptionKey(
      emscripten::val const& userId, emscripten::val const& userPublicKey) = 0;

  virtual emscripten::val putResourceKey(emscripten::val const& mac,
                                         emscripten::val const& key) = 0;
  virtual emscripten::val findResourceKey(emscripten::val const& mac) = 0;

  virtual emscripten::val getDeviceKeys() = 0;
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

  virtual emscripten::val putFullGroup(emscripten::val const& group) = 0;
  virtual emscripten::val putExternalGroup(emscripten::val const& group) = 0;
  virtual emscripten::val updateLastGroupBlock(
      emscripten::val const& groupId,
      emscripten::val const& lastBlockHash,
      emscripten::val const& lastBlockIndex) = 0;
  virtual emscripten::val findFullGroupByGroupId(
      emscripten::val const& groupId) = 0;
  virtual emscripten::val findExternalGroupByGroupId(
      emscripten::val const& groupId) = 0;
  virtual emscripten::val findFullGroupByGroupPublicEncryptionKey(
      emscripten::val const& publicEncryptionKey) = 0;
  virtual emscripten::val findExternalGroupByGroupPublicEncryptionKey(
      emscripten::val const& publicEncryptionKey) = 0;

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

  emscripten::val putUserPrivateKey(emscripten::val const& publicKey,
                                    emscripten::val const& privateKey) override
  {
    return call<emscripten::val>("putUserPrivateKey", publicKey, privateKey);
  }
  emscripten::val getUserKeyPair(emscripten::val const& publicKey) override
  {
    return call<emscripten::val>("getUserKeyPair", publicKey);
  }
  emscripten::val getUserOptLastKeyPair() override
  {
    return call<emscripten::val>("getUserOptLastKeyPair");
  }

  emscripten::val getTrustchainLastIndex() override
  {
    return call<emscripten::val>("getTrustchainLastIndex");
  }
  emscripten::val addTrustchainEntry(emscripten::val const& entry) override
  {
    return call<emscripten::val>("addTrustchainEntry", entry);
  }
  emscripten::val findTrustchainEntry(emscripten::val const& hash) override
  {
    return call<emscripten::val>("findTrustchainEntry", hash);
  }
  emscripten::val findTrustchainKeyPublish(
      emscripten::val const& resourceId) override
  {
    return call<emscripten::val>("findTrustchainKeyPublish", resourceId);
  }
  emscripten::val getTrustchainDevicesOf(emscripten::val const& userId) override
  {
    return call<emscripten::val>("getTrustchainDevicesOf", userId);
  }
  emscripten::val getTrustchainDevice(emscripten::val const& deviceId) override
  {
    return call<emscripten::val>("getTrustchainDevice", deviceId);
  }

  emscripten::val putContact(emscripten::val const& userId,
                             emscripten::val const& publicKey) override
  {
    return call<emscripten::val>("putContact", userId, publicKey);
  }
  emscripten::val findContactUserKey(emscripten::val const& userId) override
  {
    return call<emscripten::val>("findContactUserKey", userId);
  }
  emscripten::val findContactUserIdByPublicEncryptionKey(
      emscripten::val const& publicEncryptionKey) override
  {
    return call<emscripten::val>("findContactUserIdByPublicEncryptionKey",
                                 publicEncryptionKey);
  }
  emscripten::val setContactPublicEncryptionKey(
      emscripten::val const& userId,
      emscripten::val const& userPublicKey) override
  {
    return call<emscripten::val>(
        "setContactPublicEncryptionKey", userId, userPublicKey);
  }

  emscripten::val putResourceKey(emscripten::val const& mac,
                                 emscripten::val const& key) override
  {
    return call<emscripten::val>("putResourceKey", mac, key);
  }
  emscripten::val findResourceKey(emscripten::val const& mac) override
  {
    return call<emscripten::val>("findResourceKey", mac);
  }

  emscripten::val getDeviceKeys() override
  {
    return call<emscripten::val>("getDeviceKeys");
  }
  emscripten::val setDeviceKeys(emscripten::val const& deviceKeys) override
  {
    return call<emscripten::val>("setDeviceKeys", deviceKeys);
  }
  emscripten::val setDeviceId(emscripten::val const& deviceId) override
  {
    return call<emscripten::val>("setDeviceId", deviceId);
  }

  emscripten::val putDevice(emscripten::val const& userId,
                            emscripten::val const& device) override
  {
    return call<emscripten::val>("putDevice", userId, device);
  }
  emscripten::val findDevice(emscripten::val const& deviceId) override
  {
    return call<emscripten::val>("findDevice", deviceId);
  }
  emscripten::val findDeviceUserId(emscripten::val const& deviceId) override
  {
    return call<emscripten::val>("findDeviceUserId", deviceId);
  }
  emscripten::val getDevicesOf(emscripten::val const& userId) override
  {
    return call<emscripten::val>("getDevicesOf", userId);
  }
  emscripten::val updateDeviceRevokedAt(
      emscripten::val const& deviceId,
      emscripten::val const& revokedAtBlkIndex) override
  {
    return call<emscripten::val>(
        "updateDeviceRevokedAt", deviceId, revokedAtBlkIndex);
  }

  emscripten::val putFullGroup(emscripten::val const& group) override
  {
    return call<emscripten::val>("putFullGroup", group);
  }
  emscripten::val putExternalGroup(emscripten::val const& group) override
  {
    return call<emscripten::val>("putExternalGroup", group);
  }
  emscripten::val updateLastGroupBlock(
      emscripten::val const& groupId,
      emscripten::val const& lastBlockHash,
      emscripten::val const& lastBlockIndex) override
  {
    return call<emscripten::val>(
        "updateLastGroupBlock", groupId, lastBlockHash, lastBlockIndex);
  }
  emscripten::val findFullGroupByGroupId(
      emscripten::val const& groupId) override
  {
    return call<emscripten::val>("findFullGroupByGroupId", groupId);
  }
  emscripten::val findExternalGroupByGroupId(
      emscripten::val const& groupId) override
  {
    return call<emscripten::val>("findExternalGroupByGroupId", groupId);
  }
  emscripten::val findFullGroupByGroupPublicEncryptionKey(
      emscripten::val const& publicEncryptionKey) override
  {
    return call<emscripten::val>("findFullGroupByGroupPublicEncryptionKey",
                                 publicEncryptionKey);
  }
  emscripten::val findExternalGroupByGroupPublicEncryptionKey(
      emscripten::val const& publicEncryptionKey) override
  {
    return call<emscripten::val>("findExternalGroupByGroupPublicEncryptionKey",
                                 publicEncryptionKey);
  }
  emscripten::val nuke() override
  {
    return call<emscripten::val>("nuke");
  }
  emscripten::val startTransaction() override
  {
    return call<emscripten::val>("startTransaction");
  }
  emscripten::val commitTransaction() override
  {
    return call<emscripten::val>("commitTransaction");
  }
  emscripten::val rollbackTransaction() override
  {
    return call<emscripten::val>("rollbackTransaction");
  }
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
  TC_AWAIT(jsPromiseToFuture(
      _db->putUserPrivateKey(vectorToJs(publicKey), vectorToJs(privateKey))));
  TC_RETURN();
}

tc::cotask<Crypto::EncryptionKeyPair> JsDatabase::getUserKeyPair(
    Crypto::PublicEncryptionKey const& publicKey)
{
  auto const keys =
      TC_AWAIT(jsPromiseToFuture(_db->getUserKeyPair(vectorToJs(publicKey))));
  if (keys.isNull() || keys.isUndefined())
    throw DataStore::RecordNotFound("user key not found");
  TC_RETURN((Crypto::EncryptionKeyPair{
      Crypto::PublicEncryptionKey{copyToVector(keys[0])},
      Crypto::PrivateEncryptionKey{copyToVector(keys[1])}}));
}

tc::cotask<nonstd::optional<Crypto::EncryptionKeyPair>>
JsDatabase::getUserOptLastKeyPair()
{
  auto const keys = TC_AWAIT(jsPromiseToFuture(_db->getUserOptLastKeyPair()));
  if (keys.isNull() || keys.isUndefined())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN((Crypto::EncryptionKeyPair{
      Crypto::PublicEncryptionKey{copyToVector(keys[0])},
      Crypto::PrivateEncryptionKey{copyToVector(keys[1])}}));
}

tc::cotask<uint64_t> JsDatabase::getTrustchainLastIndex()
{
  TC_RETURN(static_cast<uint64_t>(
      TC_AWAIT(jsPromiseToFuture(_db->getTrustchainLastIndex())).as<double>()));
}

namespace
{
struct toVal
{
  emscripten::val operator()(TrustchainCreation const& tc)
  {
    auto ret = emscripten::val::object();
    ret.set("publicSignatureKey", vectorToJs(tc.publicSignatureKey));
    return ret;
  }
  emscripten::val operator()(DeviceCreation const& tc)
  {
    if (auto const dc1 = mpark::get_if<DeviceCreation1>(&tc.variant()))
    {
      auto ret = emscripten::val::object();
      ret.set("ephemeralPublicSignatureKey",
              vectorToJs(dc1->ephemeralPublicSignatureKey));
      ret.set("userId", vectorToJs(dc1->userId));
      ret.set("delegationSignature", vectorToJs(dc1->delegationSignature));
      ret.set("publicSignatureKey", vectorToJs(dc1->publicSignatureKey));
      ret.set("publicEncryptionKey", vectorToJs(dc1->publicEncryptionKey));
      return ret;
    }
    else if (auto const dc3 = mpark::get_if<DeviceCreation3>(&tc.variant()))
    {
      auto ret = emscripten::val::object();
      ret.set("ephemeralPublicSignatureKey",
              vectorToJs(dc3->ephemeralPublicSignatureKey));
      ret.set("userId", vectorToJs(dc3->userId));
      ret.set("delegationSignature", vectorToJs(dc3->delegationSignature));
      ret.set("publicSignatureKey", vectorToJs(dc3->publicSignatureKey));
      ret.set("publicEncryptionKey", vectorToJs(dc3->publicEncryptionKey));
      ret.set("userKeyPair", emscripten::val::object());
      ret["userKeyPair"].set("publicEncryptionKey",
                             vectorToJs(dc3->userKeyPair.publicEncryptionKey));
      ret["userKeyPair"].set(
          "encryptedPrivateEncryptionKey",
          vectorToJs(dc3->userKeyPair.encryptedPrivateEncryptionKey));
      ret.set("isGhostDevice", emscripten::val(dc3->isGhostDevice));
      return ret;
    }
    else
      throw std::runtime_error(
          "assertion failed: unsupported device creation type");
  }
  emscripten::val operator()(KeyPublishToDevice const& tc)
  {
    auto ret = emscripten::val::object();
    ret.set("recipient", vectorToJs(tc.recipient));
    ret.set("resourceId", vectorToJs(tc.mac));
    ret.set("resourceKey", vectorToJs(tc.key));
    return ret;
  }
  emscripten::val operator()(DeviceRevocation const& tc)
  {
    // TODO
    return emscripten::val::object();
  }
  emscripten::val operator()(KeyPublishToUser const& tc)
  {
    auto ret = emscripten::val::object();
    ret.set("recipientPublicEncryptionKey",
            vectorToJs(tc.recipientPublicEncryptionKey));
    ret.set("resourceId", vectorToJs(tc.mac));
    ret.set("resourceKey", vectorToJs(tc.key));
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
            vectorToJs(tc.recipientPublicEncryptionKey));
    ret.set("resourceId", vectorToJs(tc.resourceId));
    ret.set("resourceKey", vectorToJs(tc.key));
    return ret;
  }
  emscripten::val operator()(UserGroupAddition const& tc)
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
  val.set("author", emscripten::val(vectorToJs(entry.author)));
  val.set("action", mpark::visit(toVal{}, entry.action.variant()));
  val.set("hash", emscripten::val(vectorToJs(entry.hash)));
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
    entry.action = Action{TrustchainCreation{Crypto::PublicSignatureKey{
        copyToVector(jsEntry["action"]["publicSignatureKey"])}}};
  }
  else if (entry.nature == Nature::DeviceCreation ||
           entry.nature == Nature::DeviceCreation2 ||
           entry.nature == Nature::DeviceCreation3)
  {
    if (!jsEntry["action"]["userKeyPair"].isNull() &&
        !jsEntry["action"]["userKeyPair"].isUndefined())
    {
      DeviceCreation3 dc{};
      dc.userKeyPair = UserKeyPair{
          Crypto::PublicEncryptionKey{copyToVector(
              jsEntry["action"]["userKeyPair"]["publicEncryptionKey"])},
          Crypto::SealedPrivateEncryptionKey{
              copyToVector(jsEntry["action"]["userKeyPair"]
                                  ["encryptedPrivateEncryptionKey"])}};
      dc.isGhostDevice = jsEntry["action"]["isGhostDevice"].as<bool>();
      dc.userId = Crypto::Hash{copyToVector(jsEntry["action"]["userId"])};
      entry.action = Action{DeviceCreation{dc}};
    }
    else
    {
      entry.action = Action{DeviceCreation{DeviceCreation1{}}};
    }
  }
  else if (entry.nature == Nature::KeyPublishToDevice)
  {
    KeyPublishToDevice kp;
    kp.recipient = copyToVector(jsEntry["action"]["recipient"]);
    kp.mac = copyToVector(jsEntry["action"]["resourceId"]);
    kp.key = copyToVector(jsEntry["action"]["resourceKey"]);
    entry.action = kp;
  }
  else if (entry.nature == Nature::KeyPublishToUser)
  {
    KeyPublishToUser kp;
    kp.recipientPublicEncryptionKey =
        copyToVector(jsEntry["action"]["recipientPublicEncryptionKey"]);
    kp.mac = copyToVector(jsEntry["action"]["resourceId"]);
    kp.key = copyToVector(jsEntry["action"]["resourceKey"]);
    entry.action = kp;
  }
  else if (entry.nature == Nature::KeyPublishToUserGroup)
  {
    KeyPublishToUserGroup kp;
    kp.recipientPublicEncryptionKey =
        copyToVector(jsEntry["action"]["recipientPublicEncryptionKey"]);
    kp.resourceId = copyToVector(jsEntry["action"]["resourceId"]);
    kp.key = copyToVector(jsEntry["action"]["resourceKey"]);
    entry.action = kp;
  }
  else
    throw Error::formatEx<std::runtime_error>(
        "TODO: unsupported database entry type: {}",
        static_cast<int>(entry.nature));

  return entry;
}
}

tc::cotask<nonstd::optional<Entry>> JsDatabase::findTrustchainEntry(
    Crypto::Hash const& hash)
{
  auto const entry =
      TC_AWAIT(jsPromiseToFuture(_db->findTrustchainEntry(vectorToJs(hash))));
  if (entry.isNull() || entry.isUndefined())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN(jsEntryToEntry(entry));
}

tc::cotask<nonstd::optional<Entry>> JsDatabase::findTrustchainKeyPublish(
    Crypto::Mac const& resourceId)
{
  auto const entry = TC_AWAIT(
      jsPromiseToFuture(_db->findTrustchainKeyPublish(vectorToJs(resourceId))));
  if (entry.isNull() || entry.isUndefined())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN(jsEntryToEntry(entry));
}

tc::cotask<std::vector<Entry>> JsDatabase::getTrustchainDevicesOf(
    UserId const& userId)
{
  auto const entries = TC_AWAIT(
      jsPromiseToFuture(_db->getTrustchainDevicesOf(vectorToJs(userId))));

  auto const length = entries["length"].as<unsigned int>();
  std::vector<Entry> ret;
  for (auto i = 0u; i < length; ++i)
    ret.push_back(jsEntryToEntry(entries[i]));

  TC_RETURN(ret);
}

tc::cotask<Entry> JsDatabase::getTrustchainDevice(DeviceId const& deviceId)
{
  auto const jsEntry = TC_AWAIT(
      jsPromiseToFuture(_db->getTrustchainDevice(vectorToJs(deviceId))));
  if (jsEntry.isNull() || jsEntry.isUndefined())
    throw Error::formatEx<RecordNotFound>("couldn't find block with hash {}",
                                          deviceId);

  TC_RETURN(jsEntryToEntry(jsEntry));
}

tc::cotask<void> JsDatabase::putContact(
    UserId const& userId,
    nonstd::optional<Crypto::PublicEncryptionKey> const& publicKey)
{
  TC_AWAIT(jsPromiseToFuture(_db->putContact(
      vectorToJs(userId),
      publicKey ? vectorToJs(*publicKey) : emscripten::val::null())));
}

tc::cotask<nonstd::optional<Crypto::PublicEncryptionKey>>
JsDatabase::findContactUserKey(UserId const& userId)
{
  auto const key =
      TC_AWAIT(jsPromiseToFuture(_db->findContactUserKey(vectorToJs(userId))));
  if (key.isNull() || key.isUndefined())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN(Crypto::PublicEncryptionKey(copyToVector(key)));
}

tc::cotask<nonstd::optional<UserId>>
JsDatabase::findContactUserIdByPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& userPublicKey)
{
  auto const userId = TC_AWAIT(jsPromiseToFuture(
      _db->findContactUserIdByPublicEncryptionKey(vectorToJs(userPublicKey))));
  if (userId.isNull() || userId.isUndefined())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN(UserId(copyToVector(userId)));
}

tc::cotask<void> JsDatabase::setContactPublicEncryptionKey(
    UserId const& userId, Crypto::PublicEncryptionKey const& userPublicKey)
{
  TC_AWAIT(jsPromiseToFuture(_db->setContactPublicEncryptionKey(
      vectorToJs(userId), vectorToJs(userPublicKey))));
}

tc::cotask<void> JsDatabase::putResourceKey(Crypto::Mac const& mac,
                                            Crypto::SymmetricKey const& key)
{
  TC_AWAIT(
      jsPromiseToFuture(_db->putResourceKey(vectorToJs(mac), vectorToJs(key))));
}

tc::cotask<nonstd::optional<Crypto::SymmetricKey>> JsDatabase::findResourceKey(
    Crypto::Mac const& mac)
{
  auto const key =
      TC_AWAIT(jsPromiseToFuture(_db->findResourceKey(vectorToJs(mac))));
  if (key.isNull() || key.isUndefined())
    TC_RETURN(nonstd::nullopt);
  TC_RETURN(Crypto::SymmetricKey(copyToVector(key)));
}

tc::cotask<nonstd::optional<DeviceKeys>> JsDatabase::getDeviceKeys()
{
  auto const keys = TC_AWAIT(jsPromiseToFuture(_db->getDeviceKeys()));
  if (keys.isNull() || keys.isUndefined())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN((DeviceKeys{
      {Crypto::PublicSignatureKey(copyToVector(keys["publicSignatureKey"])),
       Crypto::PrivateSignatureKey(copyToVector(keys["privateSignatureKey"]))},
      {Crypto::PublicEncryptionKey(copyToVector(keys["publicEncryptionKey"])),
       Crypto::PrivateEncryptionKey(
           copyToVector(keys["privateEncryptionKey"]))},
      DeviceId(copyToVector(keys["deviceId"]))}));
}

tc::cotask<void> JsDatabase::setDeviceKeys(DeviceKeys const& deviceKeys)
{
  auto jsDeviceKeys = emscripten::val::object();
  jsDeviceKeys.set("privateSignatureKey",
                   vectorToJs(deviceKeys.signatureKeyPair.privateKey));
  jsDeviceKeys.set("publicSignatureKey",
                   vectorToJs(deviceKeys.signatureKeyPair.publicKey));
  jsDeviceKeys.set("privateEncryptionKey",
                   vectorToJs(deviceKeys.encryptionKeyPair.privateKey));
  jsDeviceKeys.set("publicEncryptionKey",
                   vectorToJs(deviceKeys.encryptionKeyPair.publicKey));
  jsDeviceKeys.set("deviceId", vectorToJs(deviceKeys.deviceId));
  TC_AWAIT(jsPromiseToFuture(_db->setDeviceKeys(jsDeviceKeys)));
}

tc::cotask<void> JsDatabase::setDeviceId(DeviceId const& deviceId)
{
  TC_AWAIT(jsPromiseToFuture(_db->setDeviceId(vectorToJs(deviceId))));
}

tc::cotask<void> JsDatabase::putDevice(UserId const& userId,
                                       Device const& device)
{
  auto jsdev = emscripten::val::object();
  jsdev.set("id", vectorToJs(device.id));
  jsdev.set("createdAtBlkIndex", static_cast<double>(device.createdAtBlkIndex));
  jsdev.set(
      "revokedAtBlkIndex",
      device.revokedAtBlkIndex ?
          emscripten::val(static_cast<double>(*device.revokedAtBlkIndex)) :
          emscripten::val::null());
  jsdev.set("publicSignatureKey", vectorToJs(device.publicSignatureKey));
  jsdev.set("publicEncryptionKey", vectorToJs(device.publicEncryptionKey));
  jsdev.set("isGhostDevice", device.isGhostDevice);
  TC_AWAIT(jsPromiseToFuture(_db->putDevice(vectorToJs(userId), jsdev)));
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
          nonstd::optional<uint64_t>{} :
          static_cast<uint64_t>(jsRevokedAt.as<double>()),
      Crypto::PublicSignatureKey(copyToVector(jsdev["publicSignatureKey"])),
      Crypto::PublicEncryptionKey(copyToVector(jsdev["publicEncryptionKey"])),
      jsdev["isGhostDevice"].as<bool>(),
  };
}
}

tc::cotask<nonstd::optional<Device>> JsDatabase::findDevice(DeviceId const& id)
{
  auto const jsdev =
      TC_AWAIT(jsPromiseToFuture(_db->findDevice(vectorToJs(id))));
  if (jsdev.isNull() || jsdev.isUndefined())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN(fromJsDevice(jsdev));
}

tc::cotask<nonstd::optional<UserId>> JsDatabase::findDeviceUserId(
    DeviceId const& id)
{
  auto const jsdev =
      TC_AWAIT(jsPromiseToFuture(_db->findDeviceUserId(vectorToJs(id))));
  if (jsdev.isNull() || jsdev.isUndefined())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN(UserId{copyToVector(jsdev)});
}

tc::cotask<void> JsDatabase::updateDeviceRevokedAt(DeviceId const& id,
                                                   uint64_t revokedAtBlkIndex)
{
  TC_AWAIT(jsPromiseToFuture(_db->updateDeviceRevokedAt(
      vectorToJs(id),
      emscripten::val(static_cast<double>(revokedAtBlkIndex)))));
}

tc::cotask<std::vector<Device>> JsDatabase::getDevicesOf(UserId const& id)
{
  auto const jsdevs =
      TC_AWAIT(jsPromiseToFuture(_db->getDevicesOf(vectorToJs(id))));

  auto const size = jsdevs["length"].as<size_t>();
  std::vector<Device> out;
  out.reserve(size);
  for (size_t i = 0; i < size; ++i)
    out.push_back(fromJsDevice(jsdevs[i]));
  TC_RETURN(out);
}

tc::cotask<void> JsDatabase::putFullGroup(Group const& group)
{
  auto jsgroup = emscripten::val::object();
  jsgroup.set("id", vectorToJs(group.id));
  jsgroup.set("publicSignatureKey",
              vectorToJs(group.signatureKeyPair.publicKey));
  jsgroup.set("privateSignatureKey",
              vectorToJs(group.signatureKeyPair.privateKey));
  jsgroup.set("publicEncryptionKey",
              vectorToJs(group.encryptionKeyPair.publicKey));
  jsgroup.set("privateEncryptionKey",
              vectorToJs(group.encryptionKeyPair.privateKey));
  jsgroup.set("lastBlockHash", vectorToJs(group.lastBlockHash));
  jsgroup.set("lastBlockIndex", static_cast<double>(group.lastBlockIndex));
  TC_AWAIT(jsPromiseToFuture(_db->putFullGroup(jsgroup)));
}

tc::cotask<void> JsDatabase::putExternalGroup(ExternalGroup const& group)
{
  auto jsgroup = emscripten::val::object();
  jsgroup.set("id", vectorToJs(group.id));
  jsgroup.set("publicSignatureKey", vectorToJs(group.publicSignatureKey));
  jsgroup.set("encryptedPrivateSignatureKey",
              group.encryptedPrivateSignatureKey ?
                  vectorToJs(*group.encryptedPrivateSignatureKey) :
                  emscripten::val::null());
  jsgroup.set("publicEncryptionKey", vectorToJs(group.publicEncryptionKey));
  jsgroup.set("lastBlockHash", vectorToJs(group.lastBlockHash));
  jsgroup.set("lastBlockIndex", static_cast<double>(group.lastBlockIndex));
  TC_AWAIT(jsPromiseToFuture(_db->putExternalGroup(jsgroup)));
}

tc::cotask<void> JsDatabase::updateLastGroupBlock(
    GroupId const& groupId,
    Crypto::Hash const& lastBlockHash,
    uint64_t lastBlockIndex)
{
  TC_AWAIT(jsPromiseToFuture(_db->updateLastGroupBlock(
      vectorToJs(groupId),
      vectorToJs(lastBlockHash),
      emscripten::val(static_cast<double>(lastBlockIndex)))));
}

namespace
{
Group fromJsFullGroup(emscripten::val const& group)
{
  return Group{
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
  return ExternalGroup{
      GroupId(copyToVector(group["id"])),
      Crypto::PublicSignatureKey(copyToVector(group["publicSignatureKey"])),
      encryptedPrivateSignatureKey.isNull() ||
              encryptedPrivateSignatureKey.isUndefined() ?
          nonstd::optional<Crypto::SealedPrivateSignatureKey>{} :
          Crypto::SealedPrivateSignatureKey(
              copyToVector(encryptedPrivateSignatureKey)),
      Crypto::PublicEncryptionKey(copyToVector(group["publicEncryptionKey"])),
      Crypto::Hash(copyToVector(group["lastBlockHash"])),
      static_cast<uint64_t>(group["lastBlockIndex"].as<double>()),
  };
}
}

tc::cotask<nonstd::optional<Group>> JsDatabase::findFullGroupByGroupId(
    GroupId const& id)
{
  auto const jsgroup =
      TC_AWAIT(jsPromiseToFuture(_db->findFullGroupByGroupId(vectorToJs(id))));
  if (jsgroup.isNull() || jsgroup.isUndefined())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN(fromJsFullGroup(jsgroup));
}

tc::cotask<nonstd::optional<ExternalGroup>>
JsDatabase::findExternalGroupByGroupId(GroupId const& id)
{
  auto const jsgroup = TC_AWAIT(
      jsPromiseToFuture(_db->findExternalGroupByGroupId(vectorToJs(id))));
  if (jsgroup.isNull() || jsgroup.isUndefined())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN(fromJsExternalGroup(jsgroup));
}

tc::cotask<nonstd::optional<Group>>
JsDatabase::findFullGroupByGroupPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey)
{
  auto const jsgroup =
      TC_AWAIT(jsPromiseToFuture(_db->findFullGroupByGroupPublicEncryptionKey(
          vectorToJs(publicEncryptionKey))));
  if (jsgroup.isNull() || jsgroup.isUndefined())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN(fromJsFullGroup(jsgroup));
}

tc::cotask<nonstd::optional<ExternalGroup>>
JsDatabase::findExternalGroupByGroupPublicEncryptionKey(
    Crypto::PublicEncryptionKey const& publicEncryptionKey)
{
  auto const jsgroup = TC_AWAIT(
      jsPromiseToFuture(_db->findExternalGroupByGroupPublicEncryptionKey(
          vectorToJs(publicEncryptionKey))));
  if (jsgroup.isNull() || jsgroup.isUndefined())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN(fromJsExternalGroup(jsgroup));
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

  emscripten::class_<std::function<void(emscripten::val const&)>>(
      "NoargOrMaybeMoreFunction")
      .constructor<>()
      .function("opcall",
                &std::function<void(emscripten::val const&)>::operator());

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
      .function("getTrustchainLastIndex",
                &JsDatabaseInterface::getTrustchainLastIndex,
                emscripten::pure_virtual())
      .function("addTrustchainEntry",
                &JsDatabaseInterface::addTrustchainEntry,
                emscripten::pure_virtual())
      .function("findTrustchainEntry",
                &JsDatabaseInterface::findTrustchainEntry,
                emscripten::pure_virtual())
      .function("findTrustchainKeyPublish",
                &JsDatabaseInterface::findTrustchainKeyPublish,
                emscripten::pure_virtual())
      .function("getTrustchainDevicesOf",
                &JsDatabaseInterface::getTrustchainDevicesOf,
                emscripten::pure_virtual())
      .function("getTrustchainDevice",
                &JsDatabaseInterface::getTrustchainDevice,
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
      .function("putResourceKey",
                &JsDatabaseInterface::putResourceKey,
                emscripten::pure_virtual())
      .function("findResourceKey",
                &JsDatabaseInterface::findResourceKey,
                emscripten::pure_virtual())
      .function("getDeviceKeys",
                &JsDatabaseInterface::getDeviceKeys,
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
      .function("putFullGroup",
                &JsDatabaseInterface::putFullGroup,
                emscripten::pure_virtual())
      .function("putExternalGroup",
                &JsDatabaseInterface::putExternalGroup,
                emscripten::pure_virtual())
      .function("updateLastGroupBlock",
                &JsDatabaseInterface::updateLastGroupBlock,
                emscripten::pure_virtual())
      .function("findFullGroupByGroupId",
                &JsDatabaseInterface::findFullGroupByGroupId,
                emscripten::pure_virtual())
      .function("findExternalGroupByGroupId",
                &JsDatabaseInterface::findExternalGroupByGroupId,
                emscripten::pure_virtual())
      .function("findFullGroupByGroupPublicEncryptionKey",
                &JsDatabaseInterface::findFullGroupByGroupPublicEncryptionKey,
                emscripten::pure_virtual())
      .function(
          "findExternalGroupByGroupPublicEncryptionKey",
          &JsDatabaseInterface::findExternalGroupByGroupPublicEncryptionKey,
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
