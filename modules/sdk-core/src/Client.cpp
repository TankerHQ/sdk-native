#include <Tanker/Client.hpp>

#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/EncryptedUserKey.hpp>
#include <Tanker/Errors/ServerErrc.hpp>
#include <Tanker/Format/Json.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/TankerSecretProvisionalIdentity.hpp>

#include <Tanker/Tracer/FuncTracer.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>

#include <cppcodec/base64_rfc4648.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <optional>
#include <utility>

using namespace Tanker::Errors;
using namespace Tanker::Trustchain;

TLOG_CATEGORY(Client);

namespace Tanker
{
namespace
{

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
    {"invalid_oidc_id_token", ServerErrc::InvalidVerificationCode},
    {"conflict", ServerErrc::Conflict},
};
}

Client::Client(Network::ConnectionPtr cx, ConnectionHandler connectionHandler)
  : _cx(std::move(cx)), _connectionHandler(std::move(connectionHandler))
{
  _cx->reconnected = [this] {
    if (_connectionHandler)
      _taskCanceler.add(tc::async_resumable(
          [this]() -> tc::cotask<void> { TC_AWAIT(handleConnection()); }));
  };
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

tc::cotask<void> Client::createUser(
    Identity::SecretPermanentIdentity const& identity,
    gsl::span<uint8_t const> userCreation,
    gsl::span<uint8_t const> firstDevice,
    Unlock::Request const& verificationRequest,
    gsl::span<uint8_t const> encryptedVerificationKey)
{
  FUNC_TIMER(Proc);
  nlohmann::json request{
      {"trustchain_id", identity.trustchainId},
      {"user_id", identity.delegation.userId},
      {"user_creation_block", cppcodec::base64_rfc4648::encode(userCreation)},
      {"first_device_block", cppcodec::base64_rfc4648::encode(firstDevice)},
      {"encrypted_unlock_key",
       cppcodec::base64_rfc4648::encode(encryptedVerificationKey)},
      {"verification", verificationRequest},
  };
  auto const reply = TC_AWAIT(emit("create user 2", request));
}

tc::cotask<void> Client::setVerificationMethod(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::UserId const& userId,
    Unlock::Request const& request)
{
  nlohmann::json payload{
      {"trustchain_id", trustchainId},
      {"user_id", userId},
      {"verification", request},
  };
  TC_AWAIT(emit("set verification method", payload));
}

tc::cotask<std::vector<std::uint8_t>> Client::fetchVerificationKey(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::UserId const& userId,
    Unlock::Request const& request)
{
  nlohmann::json payload{
      {"trustchain_id", trustchainId},
      {"user_id", userId},
      {"verification", request},
  };
  auto const response = TC_AWAIT(emit("get verification key", payload));
  TC_RETURN(cppcodec::base64_rfc4648::decode<std::vector<uint8_t>>(
      response.at("encrypted_verification_key").get<std::string>()));
}

tc::cotask<std::vector<Unlock::VerificationMethod>>
Client::fetchVerificationMethods(Trustchain::TrustchainId const& trustchainId,
                                 Trustchain::UserId const& userId)
{
  auto const request =
      nlohmann::json{{"trustchain_id", trustchainId}, {"user_id", userId}};

  auto const reply = TC_AWAIT(emit("get verification methods", request));
  auto methods = reply.at("verification_methods")
                     .get<std::vector<Unlock::VerificationMethod>>();
  TC_RETURN(methods);
}

tc::cotask<EncryptedUserKey> Client::getLastUserKey(
    Trustchain::TrustchainId const& trustchainId,
    Crypto::PublicSignatureKey const& devicePublicSignatureKey)
{
  auto const request = nlohmann::json{
      {"trustchain_id", trustchainId},
      {"device_public_signature_key", devicePublicSignatureKey},
  };

  auto const reply = TC_AWAIT(emit("last user key", request));

  EncryptedUserKey encryptedUserKey{};
  reply.at("encrypted_private_user_key")
      .get_to(encryptedUserKey.encryptedPrivateKey);
  reply.at("device_id").get_to(encryptedUserKey.deviceId);

  TC_RETURN(encryptedUserKey);
}

tc::cotask<std::vector<std::string>> Client::getBlocks(
    int lastIndex,
    std::vector<UserId> const& extra_users,
    std::vector<GroupId> const& extra_groups)
{
  auto const json = TC_AWAIT(emit("get blocks 2",
                                  {
                                      {"index", lastIndex},
                                      {"extra_users", extra_users},
                                      {"extra_groups", extra_groups},
                                      {"on_demand_key_publishes", true},
                                      {"on_demand_user_groups", true},
                                      {"on_demand_claims", true},
                                  }));
  TC_RETURN(json.get<std::vector<std::string>>());
}

tc::cotask<std::vector<std::string>> Client::getKeyPublishes(
    gsl::span<Trustchain::ResourceId const> resourceIds)
{
  auto const json =
      TC_AWAIT(emit("get key publishes", {{"resource_ids", resourceIds}}));
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
    auto const message = error_it->at("message").get<std::string>();
    auto const code = error_it->at("code").get<std::string>();
    auto const serverErrorIt = serverErrorMap.find(code);
    if (serverErrorIt == serverErrorMap.end())
      throw Errors::formatEx(
          ServerErrc::UnknownError, "code: {}, message: {}", code, message);
    throw Errors::Exception(serverErrorIt->second, message);
  }
  TC_RETURN(message);
}
}
