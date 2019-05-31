#include <Tanker/Admin.hpp>

#include <Tanker/AConnection.hpp>
#include <Tanker/Block.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/Action.hpp>
#include <Tanker/Trustchain/Actions/Nature.hpp>
#include <Tanker/Trustchain/Actions/TrustchainCreation.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <fmt/format.h>
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
    throw Error::formatEx<Error::InvalidVerificationKey>(
        "could not find verificationKey key for {}", email);
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
    auto const statusCode = error_it->at("status").get<int>();
    auto const code = error_it->at("code").get<std::string>();
    auto const message = error_it->at("message").get<std::string>();
    throw Error::ServerError{eventName, statusCode, code, message};
  }
  TC_RETURN(message);
}
}
