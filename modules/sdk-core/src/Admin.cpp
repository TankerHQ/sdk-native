#include <Tanker/Admin.hpp>

#include <Tanker/AConnection.hpp>
#include <Tanker/Action.hpp>
#include <Tanker/Actions/TrustchainCreation.hpp>
#include <Tanker/Block.hpp>
#include <Tanker/Crypto/KeyFormat.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Crypto/base64.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Nature.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Types/TrustchainId.hpp>

#include <boost/signals2/connection.hpp>
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <tconcurrent/coroutine.hpp>
#include <tconcurrent/future.hpp>
#include <tconcurrent/promise.hpp>

#include <Tanker/Tracer/ScopeTimer.hpp>

#include <algorithm>
#include <iterator>

TLOG_CATEGORY(Admin);

namespace Tanker
{
Admin::Admin(ConnectionPtr cx, std::string idToken)
  : _cx(std::move(cx)), _idToken(std::move(idToken))
{
  _cx->connected.connect([this]() {
    _taskCanceler.add(tc::async_resumable([this]() -> tc::cotask<void> {
      TC_AWAIT(authenticateCustomer(_idToken));
      connected();
    }));
  });
}

tc::cotask<void> Admin::start()
{
  tc::promise<void> prom;
  auto fut = prom.get_future();
  boost::signals2::scoped_connection c =
      connected.connect([prom = std::move(prom)]() mutable {
        prom.set_value({});
        prom = tc::promise<void>();
      });
  _cx->connect();
  TC_AWAIT(std::move(fut));
}

tc::cotask<void> Admin::authenticateCustomer(std::string const& idToken)
{
  auto const message = nlohmann::json{
      {"idToken", idToken},
  };
  TC_AWAIT(emit("authenticate customer", message));
}

tc::cotask<TrustchainId> Admin::createTrustchain(
    std::string const& name,
    Crypto::SignatureKeyPair const& keyPair,
    bool isTest)
{
  FUNC_TIMER(Net);
  Block block{};
  block.nature = Nature::TrustchainCreation;
  block.payload =
      Serialization::serialize(TrustchainCreation{keyPair.publicKey});
  block.trustchainId = gsl::make_span(block.hash());

  auto const message = nlohmann::json{
      {"is_test", isTest},
      {"name", name},
      {"root_block", base64::encode(Serialization::serialize(block))},
  };
  TC_AWAIT(emit("create trustchain", message));

  TC_RETURN(block.trustchainId);
}

tc::cotask<void> Admin::deleteTrustchain(TrustchainId const& trustchainId)
{
  auto const message = nlohmann::json{
      {"id", trustchainId},
  };
  TC_AWAIT(emit("delete trustchain", message));
}

tc::cotask<void> Admin::pushBlock(gsl::span<uint8_t const> block)
{
  TC_AWAIT(emit("push block", base64::encode(block)));
}

tc::cotask<void> Admin::pushKeys(
    std::vector<std::vector<uint8_t>> const& blocks)
{
  std::vector<std::string> sb;
  sb.reserve(blocks.size());
  std::transform(
      begin(blocks), end(blocks), std::back_inserter(sb), [](auto&& block) {
        return base64::encode(block);
      });

  TC_AWAIT(emit("push keys", sb));
}

tc::cotask<VerificationCode> Admin::getVerificationCode(
    TrustchainId const& tcid, UserId const& userId, Email const& email)
{
  auto const msg = nlohmann::json(
      {{"email", email}, {"trustchain_id", tcid}, {"user_id", userId}});

  auto const answer = TC_AWAIT(emit("get verification code", msg));
  auto it = answer.find("verification_code");
  if (it == answer.end())
    throw Error::formatEx<Error::InvalidUnlockKey>(
        "could not find unlockKey key for {} {}", userId, email);
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
