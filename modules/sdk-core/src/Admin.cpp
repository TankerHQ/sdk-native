#include <Tanker/Admin.hpp>

#include <Tanker/AConnection.hpp>
#include <Tanker/Block.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Server/Errors/Errc.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/future.hpp>
#include <tconcurrent/promise.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <algorithm>
#include <iterator>

using Tanker::Trustchain::Actions::Nature;

TLOG_CATEGORY(Admin);

namespace Tanker
{
namespace
{
// FIXME Duplicated in Client.cpp
std::map<std::string, Server::Errc> const serverErrorMap{
    {"internal_error", Server::Errc::InternalError},
    {"invalid_body", Server::Errc::InvalidBody},
    {"invalid_origin", Server::Errc::InvalidOrigin},
    {"trustchain_is_not_test", Server::Errc::TrustchainIsNotTest},
    {"trustchain_not_found", Server::Errc::TrustchainNotFound},
    {"device_not_found", Server::Errc::DeviceNotFound},
    {"device_revoked", Server::Errc::DeviceRevoked},
    {"too_many_attempts", Server::Errc::TooManyAttempts},
    {"verification_needed", Server::Errc::VerificationNeeded},
    {"invalid_passphrase", Server::Errc::InvalidPassphrase},
    {"invalid_verification_code", Server::Errc::InvalidVerificationCode},
    {"verification_code_expired", Server::Errc::VerificationCodeExpired},
    {"verification_code_not_found", Server::Errc::VerificationCodeNotFound},
    {"verification_method_not_set", Server::Errc::VerificationMethodNotSet},
    {"verification_key_not_found", Server::Errc::VerificationKeyNotFound},
    {"group_too_big", Server::Errc::GroupTooBig},
    {"invalid_delegation_signature", Server::Errc::InvalidDelegationSignature},
};
}

Admin::Admin(ConnectionPtr cx, std::string idToken)
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
    bool isTest)
{
  FUNC_TIMER(Net);
  Block block{};
  block.nature = Nature::TrustchainCreation;
  block.payload = Serialization::serialize(
      Trustchain::Actions::TrustchainCreation{keyPair.publicKey});
  block.trustchainId = Trustchain::TrustchainId(block.hash());

  auto const message = nlohmann::json{
      {"is_test", isTest},
      {"name", name},
      {"root_block",
       cppcodec::base64_rfc4648::encode(Serialization::serialize(block))},
  };
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

tc::cotask<void> Admin::pushBlock(gsl::span<uint8_t const> block)
{
  TC_AWAIT(emit("push block", cppcodec::base64_rfc4648::encode(block)));
}

tc::cotask<void> Admin::pushKeys(
    std::vector<std::vector<uint8_t>> const& blocks)
{
  std::vector<std::string> sb;
  sb.reserve(blocks.size());
  std::transform(
      begin(blocks), end(blocks), std::back_inserter(sb), [](auto&& block) {
        return cppcodec::base64_rfc4648::encode(block);
      });

  TC_AWAIT(emit("push keys", sb));
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
          Server::Errc::UnknownError, "code: {}, message: {}", code, message);
    throw Errors::Exception(serverErrorIt->second, message);
  }
  TC_RETURN(message);
}
}
