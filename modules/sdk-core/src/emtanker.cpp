#include <Tanker/Actions/TrustchainCreation.hpp>
#include <Tanker/Admin.hpp>
#include <Tanker/AsyncCore.hpp>
#include <Tanker/Block.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Crypto/base64.hpp>
#include <Tanker/Emscripten/Helpers.hpp>
#include <Tanker/Encryptor.hpp>
#include <Tanker/Entry.hpp>
#include <Tanker/Identity/SecretPermanentIdentity.hpp>
#include <Tanker/Init.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Opener.hpp>

#include <emscripten.h>
#include <emscripten/bind.h>

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
                base64::decode<TrustchainId>(std::move(trustchainId)),
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
      [=](char const*, char, char const* msg) { cb(emscripten::val(msg)); });
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
      .function("encryptedSize", &CoreEncryptedSize)
      .function("decryptedSize", &CoreDecryptedSize)
      .function("encrypt", &CoreEncrypt, emscripten::allow_raw_pointers())
      .function("decrypt", &CoreDecrypt, emscripten::allow_raw_pointers());
}
