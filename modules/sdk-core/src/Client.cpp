#include <Tanker/Client.hpp>

#include <Tanker/AConnection.hpp>
#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/EncryptedUserKey.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Format/Json.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Unlock/Messages.hpp>

#include <Tanker/Tracer/FuncTracer.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <fmt/format.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <utility>

TLOG_CATEGORY(Client);

namespace Tanker
{

Client::Client(std::unique_ptr<AConnection> cx,
               ConnectionHandler connectionHandler)
  : _cx(std::move(cx)), _connectionHandler(std::move(connectionHandler))
{
  _cx->on("new relevant block", [this](auto const& e) { blockAvailable(); });
  _cx->reconnected.connect([this]() {
    if (_connectionHandler)
      _taskCanceler.add(tc::async_resumable(
          [this]() -> tc::cotask<void> { TC_AWAIT(handleConnection()); }));
  });
}

void Client::start()
{
  FUNC_BEGIN("client connection", Net);
  _cx->connect();
}

std::string Client::connectionId() const
{
  return this->_cx->id();
}

void Client::setConnectionHandler(ConnectionHandler handler)
{
  assert(handler);
  _connectionHandler = std::move(handler);
}

tc::cotask<void> Client::handleConnection()
{
  FUNC_TIMER(Net);
  TC_AWAIT(_connectionHandler());
  FUNC_END("client connection", Net);
}

tc::cotask<void> Client::pushBlock(gsl::span<uint8_t const> block)
{
  TC_AWAIT(emit("push block", cppcodec::base64_rfc4648::encode(block)));
}

tc::cotask<void> Client::pushKeys(gsl::span<std::vector<uint8_t> const> blocks)
{
  std::vector<std::string> sb;
  sb.reserve(blocks.size());
  std::transform(
      begin(blocks), end(blocks), std::back_inserter(sb), [](auto&& block) {
        return cppcodec::base64_rfc4648::encode(block);
      });

  TC_AWAIT(emit("push keys", sb));
}

tc::cotask<UserStatusResult> Client::userStatus(
    TrustchainId const& trustchainId,
    UserId const& userId,
    Crypto::PublicSignatureKey const& publicSignatureKey)
{
  FUNC_TIMER(Proc);
  nlohmann::json request{
      {"trustchain_id", trustchainId},
      {"user_id", userId},
      {"device_public_signature_key", publicSignatureKey},
  };

  auto const reply = TC_AWAIT(emit("get user status", request));

  TC_RETURN(reply.get<UserStatusResult>());
}

tc::cotask<void> Client::createUnlockKey(Unlock::Message const& message)
{
  TC_AWAIT(emit("create unlock key", message));
}

tc::cotask<void> Client::updateUnlockKey(Unlock::Message const& message)
{
  TC_AWAIT(emit("update unlock key", message));
}

tc::cotask<Unlock::FetchAnswer> Client::fetchUnlockKey(
    Unlock::Request const& req)
{
  TC_RETURN(TC_AWAIT(emit("get unlock key", req)));
}

tc::cotask<std::string> Client::requestAuthChallenge()
{
  TC_RETURN(TC_AWAIT(emit("request auth challenge", {}))
                .at("challenge")
                .get<std::string>());
}

tc::cotask<Unlock::Methods> Client::authenticateDevice(
    nlohmann::json const& request)
{
  auto const response = TC_AWAIT(emit("authenticate device", request));
  auto const it = response.find("unlock_methods");
  if (it == response.end())
    TC_RETURN(Unlock::Method{});
  TC_RETURN(it.value().get<Unlock::Methods>());
}

tc::cotask<EncryptedUserKey> Client::getLastUserKey(
    TrustchainId const& trustchainId, DeviceId const& deviceId)
{
  auto const request = nlohmann::json{
      {"trustchain_id", trustchainId},
      {"device_id", deviceId},
  };

  auto const reply = TC_AWAIT(emit("last user key", request));

  TC_RETURN((EncryptedUserKey{
      reply.at("public_user_key").get<Crypto::PublicEncryptionKey>(),
      reply.at("encrypted_private_user_key")
          .get<Crypto::SealedPrivateEncryptionKey>(),
  }));
}

tc::cotask<void> Client::subscribeToCreation(
    TrustchainId const& trustchainId,
    Crypto::PublicSignatureKey const& publicKey,
    Crypto::Signature const& signedPublicKey)
{
  _cx->on("device created", [this](auto const& e) { this->deviceCreated(); });
  auto p = nlohmann::json{
      {"trustchain_id", trustchainId},
      {"public_signature_key", publicKey},
      {"signature", signedPublicKey},
  };
  TC_AWAIT(emit("subscribe to creation", p));
}

tc::cotask<std::vector<std::string>> Client::getBlocks(
    int lastIndex,
    std::vector<UserId> const& extra_users,
    std::vector<GroupId> const& extra_groups)
{
  auto const json = TC_AWAIT(emit("get blocks 2",
                                  {{"index", lastIndex},
                                   {"extra_users", extra_users},
                                   {"extra_groups", extra_groups}}));
  TC_RETURN(json.get<std::vector<std::string>>());
}

tc::cotask<nlohmann::json> Client::emit(std::string const& eventName,
                                        nlohmann::json const& data)
{
  auto const stringmessage = TC_AWAIT(_cx->emit(
      eventName,
      eventName == "push block" ? data.get<std::string>() : data.dump()));
  TDEBUG("emit({:s}, {:j}) -> {:s}", eventName, data, stringmessage);
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

void from_json(nlohmann::json const& j, UserStatusResult& result)
{
  j.at("device_exists").get_to(result.deviceExists);
  result.userExists = j.at("user_exists").get<bool>();
  auto const lastReset = j.at("last_reset").get<std::string>();
  if (!lastReset.empty())
    result.lastReset =
        cppcodec::base64_rfc4648::decode<Crypto::Hash>(lastReset);
  else
    result.lastReset = Crypto::Hash{};
}
} // Tanker
