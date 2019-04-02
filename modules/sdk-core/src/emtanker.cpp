#include <Tanker/Actions/TrustchainCreation.hpp>
#include <Tanker/Admin.hpp>
#include <Tanker/AsyncCore.hpp>
#include <Tanker/Block.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Emscripten/Helpers.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Init.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Opener.hpp>

#include <emscripten.h>
#include <emscripten/bind.h>

#include <cppcodec/base64_rfc4648.hpp>
#include <sodium/randombytes.h>

#include <iostream>

using namespace Tanker;

TLOG_CATEGORY(em);

namespace
{
AsyncCore* makeCore(std::string trustchainId,
                    std::string url,
                    std::string writablePath)
{
  try
  {
    return new AsyncCore(std::move(url),
                         SdkInfo{"client-emscripten",
                                 cppcodec::base64_rfc4648::decode<TrustchainId>(
                                     std::move(trustchainId)),
                                 "0.0.1"},
                         std::move(writablePath));
  }
  catch (std::exception const& e)
  {
    TERROR("Can't create Tanker: {}: {}", typeid(e).name(), e.what());
    return nullptr;
  }
}

emscripten::val CoreSignUp(AsyncCore& core,
                           std::string const& identity,
                           emscripten::val const& jauthenticationMethods)
{
  AuthenticationMethods authenticationMethods;
  authenticationMethods.password = Emscripten::optionalFromValue<Password>(
      jauthenticationMethods, "password");
  authenticationMethods.email =
      Emscripten::optionalFromValue<Email>(jauthenticationMethods, "email");
  return Emscripten::tcFutureToJsPromise(
      core.signUp(identity, authenticationMethods));
}

emscripten::val CoreSignIn(AsyncCore& core,
                           std::string const& identity,
                           emscripten::val const& jsignInOptions)
{
  SignInOptions signInOptions;
  signInOptions.unlockKey =
      Emscripten::optionalFromValue<UnlockKey>(jsignInOptions, "unlockKey");
  signInOptions.verificationCode =
      Emscripten::optionalFromValue<VerificationCode>(jsignInOptions,
                                                      "verificationCode");
  signInOptions.password =
      Emscripten::optionalFromValue<Password>(jsignInOptions, "password");
  return Emscripten::tcFutureToJsPromise(core.signIn(identity, signInOptions));
}

emscripten::val CoreIsOpen(AsyncCore& core)
{
  return emscripten::val(core.isOpen());
}

emscripten::val CoreEncrypt(AsyncCore& core,
                            uintptr_t iencryptedData,
                            uintptr_t iclearData,
                            uint32_t clearSize)
{
  auto const encryptedData = reinterpret_cast<uint8_t*>(iencryptedData);
  auto const clearData = reinterpret_cast<uint8_t const*>(iclearData);
  return Emscripten::tcFutureToJsPromise(core.encrypt(
      encryptedData, gsl::span<uint8_t const>(clearData, clearSize)));
}

emscripten::val CoreDecrypt(AsyncCore& core,
                            uintptr_t idecryptedData,
                            uintptr_t iencryptedData,
                            uint32_t encryptedSize)
{
  auto const decryptedData = reinterpret_cast<uint8_t*>(idecryptedData);
  auto const encryptedData = reinterpret_cast<uint8_t const*>(iencryptedData);
  return Emscripten::tcFutureToJsPromise(core.decrypt(
      decryptedData, gsl::span<uint8_t const>(encryptedData, encryptedSize)));
}

emscripten::val CoreShare(AsyncCore& core,
                          emscripten::val const& jresourceIds,
                          emscripten::val const& jpublicIdentities,
                          emscripten::val const& jgroupIds)
{
  auto const resourceIds =
      Emscripten::copyToStringLikeVector<SResourceId>(jresourceIds);
  auto const publicIdentities =
      Emscripten::copyToStringLikeVector<SPublicIdentity>(jpublicIdentities);
  auto const groupIds = Emscripten::copyToStringLikeVector<SGroupId>(jgroupIds);
  return Emscripten::tcFutureToJsPromise(
      core.share(resourceIds, publicIdentities, groupIds));
}

emscripten::val CoreCreateGroup(AsyncCore& core, emscripten::val const& members)
{
  auto const publicIdentities =
      Emscripten::copyToStringLikeVector<SPublicIdentity>(members);
  return Emscripten::tcFutureToJsPromise(
      core.createGroup(publicIdentities).and_then([](auto const& groupId) {
        return groupId.string();
      }));
}

emscripten::val CoreUpdateGroupMembers(AsyncCore& core,
                                       emscripten::val const& jgroupId,
                                       emscripten::val const& jusersToAdd)
{
  auto const usersToAdd =
      Emscripten::copyToStringLikeVector<SPublicIdentity>(jusersToAdd);
  return Emscripten::tcFutureToJsPromise(core.updateGroupMembers(
      SGroupId(jgroupId.as<std::string>()), usersToAdd));
}

emscripten::val CoreGenerateAndRegisterUnlockKey(AsyncCore& core)
{
  return Emscripten::tcFutureToJsPromise(
      core.generateAndRegisterUnlockKey().and_then(
          [](auto const& unlockKey) { return unlockKey.string(); }));
}

emscripten::val CoreRegisterUnlock(AsyncCore& core,
                                   emscripten::val const& unlockMethods)
{
  Unlock::RegistrationOptions o;
  if (auto const email =
          Emscripten::optionalFromValue<Email>(unlockMethods, "email"))
    o.set(*email);
  if (auto const password =
          Emscripten::optionalFromValue<Password>(unlockMethods, "password"))
    o.set(*password);
  return Emscripten::tcFutureToJsPromise(core.registerUnlock(o));
}

emscripten::val CoreIsUnlockAlreadySetUp(AsyncCore& core)
{
  return Emscripten::tcFutureToJsPromise(core.isUnlockAlreadySetUp());
}

emscripten::val CoreHasRegisteredUnlockMethods(AsyncCore& core)
{
  return Emscripten::tcExpectedToJsValue(core.hasRegisteredUnlockMethods());
}

emscripten::val CoreHasRegisteredUnlockMethod(AsyncCore& core,
                                              emscripten::val const& jmethod)
{
  auto const smethod = jmethod.as<std::string>();
  Unlock::Method method;
  if (smethod == "password")
    method = Unlock::Method::Password;
  else if (smethod == "email")
    method = Unlock::Method::Email;
  else
    return emscripten::val(false);

  return Emscripten::tcExpectedToJsValue(
      core.hasRegisteredUnlockMethod(method));
}

namespace
{
emscripten::val toUnlockMethod(std::string const& name)
{
  auto o = emscripten::val::object();
  o.set("type", name);
  return o;
}
}

emscripten::val CoreRegisteredUnlockMethods(AsyncCore& core)
{
  return Emscripten::tcExpectedToJsValue(
      core.registeredUnlockMethods().and_then(
          tc::get_synchronous_executor(), [](auto const& methods) {
            auto const ret = emscripten::val::array();
            if (methods & Unlock::Method::Email)
              ret.call<void>("push", toUnlockMethod("email"));
            if (methods & Unlock::Method::Password)
              ret.call<void>("push", toUnlockMethod("password"));
            return ret;
          }));
}

emscripten::val CoreRevokeDevice(AsyncCore& core, std::string const& deviceId)
{
  return Emscripten::tcFutureToJsPromise(
      core.revokeDevice(SDeviceId(deviceId)));
}

emscripten::val CoreDeviceId(AsyncCore& core)
{
  return Emscripten::tcExpectedToJsValue(core.deviceId().and_then(
      tc::get_synchronous_executor(),
      [](auto const& deviceId) { return deviceId.string(); }));
}

// There is no disconnect function because the JS just subscribes to this event
// for the whole lifetime of the object. User connections are handled by
// EventEmitter directly in JS.
void CoreConnectDeviceRevoked(AsyncCore& core, emscripten::val const& cb)
{
  core.deviceRevoked().connect(cb);
}

uint32_t CoreEncryptedSize(AsyncCore&, uint32_t clearSize)
{
  return Encryptor::encryptedSize(clearSize);
}

uint32_t CoreDecryptedSize(AsyncCore&,
                           uintptr_t iencryptedData,
                           uint32_t encryptedSize)
{
  auto const encryptedData = reinterpret_cast<uint8_t const*>(iencryptedData);
  return Encryptor::decryptedSize(
      gsl::span<uint8_t const>(encryptedData, encryptedSize));
}

std::string TankerCreateIdentity(std::string const& trustchainId,
                                 std::string const& trustchainPrivateKey,
                                 std::string const& userId)
{
  return Identity::createIdentity(
      trustchainId, trustchainPrivateKey, SUserId(userId));
}

using LogCallback = std::function<void(emscripten::val const&)>;
void TankerSetLogHandler(emscripten::val const& cb)
{
  Log::setLogHandler(
      [=](auto const& record) { cb(emscripten::val(record.message)); });
}
}

EMSCRIPTEN_BINDINGS(Tanker)
{
  emscripten::enum_<OpenResult>("SignInResult")
      .value("Ok", OpenResult::Ok)
      .value("IdentityNotRegistered", OpenResult::IdentityNotRegistered)
      .value("IdentityVerificationNeeded",
             OpenResult::IdentityVerificationNeeded);

  emscripten::function("setLogHandler", &TankerSetLogHandler);

  emscripten::function("createIdentity", TankerCreateIdentity);

  emscripten::function("init", Tanker::init);

  emscripten::class_<AsyncCore>("Tanker")
      .constructor(&makeCore)
      .function("signUp", &CoreSignUp)
      .function("signIn", &CoreSignIn)
      .function("isOpen", &CoreIsOpen)
      .function("encryptedSize", &CoreEncryptedSize)
      .function("decryptedSize", &CoreDecryptedSize)
      .function("encrypt", &CoreEncrypt, emscripten::allow_raw_pointers())
      .function("decrypt", &CoreDecrypt, emscripten::allow_raw_pointers())
      .function("share", &CoreShare)
      .function("createGroup", &CoreCreateGroup)
      .function("updateGroupMembers", &CoreUpdateGroupMembers)
      .function("generateAndRegisterUnlockKey",
                &CoreGenerateAndRegisterUnlockKey)
      .function("registerUnlock", &CoreRegisterUnlock)
      .function("isUnlockAlreadySetUp", &CoreIsUnlockAlreadySetUp)
      .function("hasRegisteredUnlockMethods", &CoreHasRegisteredUnlockMethods)
      .function("hasRegisteredUnlockMethod", &CoreHasRegisteredUnlockMethod)
      .function("registeredUnlockMethods", &CoreRegisteredUnlockMethods)
      .function("deviceId", &CoreDeviceId)
      .function("revokeDevice", &CoreRevokeDevice)
      .function("connectDeviceRevoked", &CoreConnectDeviceRevoked);
}
