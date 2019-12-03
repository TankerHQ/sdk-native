#include <Tanker/Admin/Admin.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Errors/ServerErrc.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Network/AConnection.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>
#include <Tanker/Trustchain/Block.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/future.hpp>
#include <tconcurrent/promise.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <algorithm>
#include <iterator>

using namespace Tanker::Errors;
using Tanker::Trustchain::Actions::Nature;

TLOG_CATEGORY(Admin);

namespace Tanker
{
namespace Admin
{
namespace
{
// FIXME Duplicated in Client.cpp
std::map<std::string, ServerErrc> const serverErrorMap{
    {"internal_error", ServerErrc::InternalError},
    {"invalid_body", ServerErrc::InvalidBody},
    {"invalid_origin", ServerErrc::InvalidOrigin},
    {"trustchain_is_not_test", ServerErrc::TrustchainIsNotTest},
    {"trustchain_not_found", ServerErrc::TrustchainNotFound},
    {"device_not_found", ServerErrc::DeviceNotFound},
    {"device_revoked", ServerErrc::DeviceRevoked},
    {"too_many_attempts", ServerErrc::TooManyAttempts},
    {"verification_needed", ServerErrc::VerificationNeeded},
    {"invalid_passphrase", ServerErrc::InvalidPassphrase},
    {"invalid_verification_code", ServerErrc::InvalidVerificationCode},
    {"verification_code_expired", ServerErrc::VerificationCodeExpired},
    {"verification_code_not_found", ServerErrc::VerificationCodeNotFound},
    {"verification_method_not_set", ServerErrc::VerificationMethodNotSet},
    {"verification_key_not_found", ServerErrc::VerificationKeyNotFound},
    {"group_too_big", ServerErrc::GroupTooBig},
    {"invalid_delegation_signature", ServerErrc::InvalidDelegationSignature},
};
}

Admin::Admin(Network::ConnectionPtr cx, std::string idToken)
  : _cx(std::move(cx)), _idToken(std::move(idToken))
{
  _cx->connected = [this]() {
    _taskCanceler.add(tc::async_resumable([this]() -> tc::cotask<void> {
      TC_AWAIT(authenticateCustomer(_idToken));
      connected();
    }));
  };
}

tc::cotask<void> Admin::start()
{
  tc::promise<void> prom;
  auto fut = prom.get_future();
  this->connected = ([prom = std::move(prom)]() mutable {
    prom.set_value({});
    prom = tc::promise<void>();
  });
  _cx->connect();
  TC_AWAIT(std::move(fut));
  connected = nullptr;
}

tc::cotask<void> Admin::authenticateCustomer(std::string const& idToken)
{
  auto const message = nlohmann::json{
      {"idToken", idToken},
  };
  TC_AWAIT(emit("authenticate customer", message));
}

tc::cotask<Trustchain::TrustchainId> Admin::createTrustchain(
    std::string const& name,
    Crypto::SignatureKeyPair const& keyPair,
    bool isTest,
    bool storePrivateKey)
{
  FUNC_TIMER(Net);
  Trustchain::Block block{};
  block.nature = Nature::TrustchainCreation;
  block.payload = Serialization::serialize(
      Trustchain::Actions::TrustchainCreation{keyPair.publicKey});
  block.trustchainId = Trustchain::TrustchainId(block.hash());

  auto message = nlohmann::json{
      {"is_test", isTest},
      {"name", name},
      {"root_block",
       cppcodec::base64_rfc4648::encode(Serialization::serialize(block))},
  };
  if (storePrivateKey)
    message["private_signature_key"] = keyPair.privateKey;
  TC_AWAIT(emit("create trustchain", message));

  TC_RETURN(block.trustchainId);
}

tc::cotask<void> Admin::deleteTrustchain(
    Trustchain::TrustchainId const& trustchainId)
{
  auto const message = nlohmann::json{
      {"id", trustchainId},
  };
  TC_AWAIT(emit("delete trustchain", message));
}

tc::cotask<void> Admin::update(Trustchain::TrustchainId const& trustchainId,
                               std::optional<std::string> oidcClientId,
                               std::optional<std::string> oidcProvider)
{
  auto request = nlohmann::json{{"id", trustchainId}};
  if (oidcClientId)
    request["oidc_client_id"] = oidcClientId.value();
  if (oidcProvider)
    request["oidc_provider"] = oidcProvider.value();
  TC_AWAIT(emit("update trustchain", request));
}

tc::cotask<VerificationCode> Admin::getVerificationCode(
    Trustchain::TrustchainId const& tcid, Email const& email)
{
  auto const msg = nlohmann::json({{"email", email}, {"trustchain_id", tcid}});

  auto const answer = TC_AWAIT(emit("get verification code", msg));
  auto it = answer.find("verification_code");
  if (it == answer.end())
  {
    throw Errors::formatEx(Errors::Errc::InvalidVerification,
                           "could not find verification code for {}",
                           email);
  }
  TC_RETURN(it->get<std::string>());
}

tc::cotask<nlohmann::json> Admin::emit(std::string const& eventName,
                                       nlohmann::json const& data)
{
  auto const stringmessage = TC_AWAIT(_cx->emit(eventName, data.dump()));
  TDEBUG("emit({}) -> {}", eventName, stringmessage);
  auto const message = nlohmann::json::parse(stringmessage);
  auto const error_it = message.find("error");
  if (error_it != message.end())
  {
    auto const code = error_it->at("code").get<std::string>();
    auto const message = error_it->at("message").get<std::string>();
    auto const serverErrorIt = serverErrorMap.find(code);
    if (serverErrorIt == serverErrorMap.end())
      throw Errors::formatEx(
          ServerErrc::UnknownError, "code: {}, message: {}", code, message);
    throw Errors::Exception(serverErrorIt->second, message);
  }
  TC_RETURN(message);
}
}
}
