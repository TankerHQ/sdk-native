#include <Tanker/Admin.hpp>
#include <Tanker/AsyncCore.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Emscripten/Helpers.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Init.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Opener.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

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
    return new AsyncCore(
        std::move(url),
        SdkInfo{"client-emscripten",
                cppcodec::base64_rfc4648::decode<Trustchain::TrustchainId>(
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

Unlock::Verification jverificationToVerification(
    emscripten::val const& jverification)
{
  if (Emscripten::isNone(jverification))
    throw Errors::Exception(make_error_code(Errors::Errc::InvalidArgument),
                            "verification is null");

  Unlock::Verification verification;
  if (!Emscripten::isNone(jverification["verificationKey"]))
    verification =
        VerificationKey(jverification["verificationKey"].as<std::string>());
  else if (!Emscripten::isNone(jverification["passphrase"]))
    verification = Passphrase(jverification["passphrase"].as<std::string>());
  else if (!Emscripten::isNone(jverification["email"]) &&
           !Emscripten::isNone(jverification["verificationCode"]))
    verification = Unlock::EmailVerification{
        Email(jverification["email"].as<std::string>()),
        VerificationCode(jverification["verificationCode"].as<std::string>())};
  else
    throw Errors::Exception(make_error_code(Errors::Errc::InvalidArgument),
                            "invalid verification");
  return verification;
}

emscripten::val toVerificationMethod(Unlock::VerificationMethod const& method)
{
  auto o = emscripten::val::object();
  if (method.holds_alternative<Passphrase>())
  {
    o.set("type", "passphrase");
  }
  else if (method.holds_alternative<VerificationKey>())
  {
    o.set("type", "verificationKey");
  }
  else if (method.holds_alternative<Email>())
  {
    o.set("type", "email");
    o.set("email", method.get<Email>().string());
  }
  return o;
}

emscripten::val CoreStart(AsyncCore& core, std::string const& identity)
{
  return Emscripten::tcFutureToJsPromise(core.start(identity));
}

emscripten::val CoreRegisterIdentity(AsyncCore& core,
                                     emscripten::val const& jverification)
{
  return Emscripten::tcFutureToJsPromise(
      tc::sync([&] {
        return core.registerIdentity(
            jverificationToVerification(jverification));
      })
          .unwrap());
}

emscripten::val CoreVerifyIdentity(AsyncCore& core,
                                   emscripten::val const& jverification)
{
  return Emscripten::tcFutureToJsPromise(
      tc::sync([&] {
        return core.verifyIdentity(jverificationToVerification(jverification));
      })
          .unwrap());
}

emscripten::val CoreStatus(AsyncCore& core)
{
  return emscripten::val(core.status());
}

emscripten::val CoreEncrypt(AsyncCore& core,
                            uintptr_t iencryptedData,
                            uintptr_t iclearData,
                            uint32_t clearSize,
                            emscripten::val const& shareWithUsers,
                            emscripten::val const& shareWithGroups)
{
  auto const encryptedData = reinterpret_cast<uint8_t*>(iencryptedData);
  auto const clearData = reinterpret_cast<uint8_t const*>(iclearData);
  auto const publicIdentities =
      Emscripten::copyToStringLikeVector<SPublicIdentity>(shareWithUsers);
  auto const groupIds =
      Emscripten::copyToStringLikeVector<SGroupId>(shareWithGroups);
  return Emscripten::tcFutureToJsPromise(
      core.encrypt(encryptedData,
                   gsl::span<uint8_t const>(clearData, clearSize),
                   publicIdentities,
                   groupIds));
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
      core.createGroup(publicIdentities)
          .and_then(tc::get_synchronous_executor(),
                    [](auto const& groupId) { return groupId.string(); }));
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

emscripten::val CoreAttachProvisionalIdentity(
    AsyncCore& core, emscripten::val const& secretProvisionalIdentity)
{
  return Emscripten::tcFutureToJsPromise(
      core
          .attachProvisionalIdentity(SSecretProvisionalIdentity(
              secretProvisionalIdentity.as<std::string>()))
          .and_then(
              tc::get_synchronous_executor(), [](auto const& attachResult) {
                emscripten::val ret = emscripten::val::object();
                ret.set("status", static_cast<int>(attachResult.status));
                if (attachResult.verificationMethod)
                  ret.set(
                      "verificationMethod",
                      toVerificationMethod(*attachResult.verificationMethod));
                return ret;
              }));
}

emscripten::val CoreVerifyProvisionalIdentity(
    AsyncCore& core, emscripten::val const& jverification)
{
  return Emscripten::tcFutureToJsPromise(
      tc::sync([&] {
        return core.verifyProvisionalIdentity(
            jverificationToVerification(jverification));
      })
          .unwrap());
}

emscripten::val CoreGenerateVerificationKey(AsyncCore& core)
{
  return Emscripten::tcFutureToJsPromise(
      core.generateVerificationKey().and_then(tc::get_synchronous_executor(),
                                              [](auto const& verificationKey) {
                                                return verificationKey.string();
                                              }));
}

emscripten::val CoreSetVerificationMethod(AsyncCore& core,
                                          emscripten::val const& jverification)
{
  return Emscripten::tcFutureToJsPromise(
      tc::sync([&] {
        return core.setVerificationMethod(
            jverificationToVerification(jverification));
      })
          .unwrap());
}

emscripten::val CoreGetVerificationMethods(AsyncCore& core)
{
  return Emscripten::tcFutureToJsPromise(core.getVerificationMethods().and_then(
      tc::get_synchronous_executor(), [](auto const& methods) {
        auto const ret = emscripten::val::array();
        for (auto const& method : methods)
          ret.call<void>("push", toVerificationMethod(method));
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

emscripten::val CoreGetDeviceList(AsyncCore& core)
{
  return Emscripten::tcFutureToJsPromise(core.getDeviceList().and_then(
      tc::get_synchronous_executor(), [](auto const& devices) {
        auto ret = emscripten::val::array();
        for (auto const& device : devices)
        {
          auto jdevice = emscripten::val::object();
          jdevice.set("id", cppcodec::base64_rfc4648::encode(device.id));
          jdevice.set("isRevoked", device.revokedAtBlkIndex.has_value());
          ret.call<void>("push", jdevice);
        }
        return ret;
      }));
}

void CoreConnectDeviceRevoked(AsyncCore& core, emscripten::val const& cb)
{
  core.connectDeviceRevoked(cb);
}

emscripten::val CoreSyncTrustchain(AsyncCore& core)
{
  return Emscripten::tcFutureToJsPromise(core.syncTrustchain());
}

uint32_t CoreEncryptedSize(AsyncCore&, uint32_t clearSize)
{
  return Encryptor::encryptedSize(clearSize);
}

emscripten::val CoreDecryptedSize(AsyncCore&,
                                  uintptr_t iencryptedData,
                                  uint32_t encryptedSize)
{
  try
  {
    auto const encryptedData = reinterpret_cast<uint8_t const*>(iencryptedData);
    return emscripten::val(static_cast<double>(Encryptor::decryptedSize(
        gsl::span<uint8_t const>(encryptedData, encryptedSize))));
  }
  catch (...)
  {
    return Emscripten::currentExceptionToJs();
  }
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
  emscripten::enum_<Status>("Status")
      .value("STOPPED", Status::Stopped)
      .value("READY", Status::Ready)
      .value("IDENTITY_REGISTRATION_NEEDED", Status::IdentityRegistrationNeeded)
      .value("IDENTITY_VERIFICATION_NEEDED",
             Status::IdentityVerificationNeeded);

  emscripten::function("setLogHandler", &TankerSetLogHandler);

  emscripten::function("createIdentity", TankerCreateIdentity);

  emscripten::function("init", Tanker::init);

  emscripten::class_<AsyncCore>("Tanker")
      .constructor(&makeCore)
      .function("start", &CoreStart)
      .function("registerIdentity", &CoreRegisterIdentity)
      .function("verifyIdentity", &CoreVerifyIdentity)
      .function("status", &CoreStatus)
      .function("encryptedSize", &CoreEncryptedSize)
      .function("decryptedSize", &CoreDecryptedSize)
      .function("encrypt", &CoreEncrypt, emscripten::allow_raw_pointers())
      .function("decrypt", &CoreDecrypt, emscripten::allow_raw_pointers())
      .function("share", &CoreShare)
      .function("createGroup", &CoreCreateGroup)
      .function("updateGroupMembers", &CoreUpdateGroupMembers)
      .function("attachProvisionalIdentity", &CoreAttachProvisionalIdentity)
      .function("verifyProvisionalIdentity", &CoreVerifyProvisionalIdentity)
      .function("generateVerificationKey", &CoreGenerateVerificationKey)
      .function("setVerificationMethod", &CoreSetVerificationMethod)
      .function("getVerificationMethods", &CoreGetVerificationMethods)
      .function("deviceId", &CoreDeviceId)
      .function("getDeviceList", &CoreGetDeviceList)
      .function("revokeDevice", &CoreRevokeDevice)
      .function("connectDeviceRevoked", &CoreConnectDeviceRevoked)
      .function("syncTrustchain", &CoreSyncTrustchain);
}
