#include <Tanker/Client.hpp>

#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/EncryptedUserKey.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Format/Json.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/ServerError.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/TankerSecretProvisionalIdentity.hpp>
#include <Tanker/Unlock/Messages.hpp>
#include <Tanker/Unlock/Verification.hpp>

#include <Tanker/Tracer/FuncTracer.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>

#include <cppcodec/base64_rfc4648.hpp>

#include <nlohmann/json.hpp>
#include <optional.hpp>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <utility>

using Tanker::Trustchain::GroupId;
using Tanker::Trustchain::UserId;

TLOG_CATEGORY(Client);

namespace Tanker
{

Client::Client(ConnectionPtr cx, ConnectionHandler connectionHandler)
  : _cx(std::move(cx)), _connectionHandler(std::move(connectionHandler))
{
  _cx->on("new relevant block", [this](auto const& e) { blockAvailable(); });
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
    Block const& userCreation,
    Block const& firstDevice,
    Unlock::Verification const& method,
    Crypto::SymmetricKey userSecret,
    gsl::span<uint8_t const> encryptedVerificationKey)
{
  FUNC_TIMER(Proc);
  nlohmann::json request{
      {"trustchain_id", identity.trustchainId},
      {"user_id", identity.delegation.userId},
      {"user_creation_block", userCreation},
      {"first_device_block", firstDevice},
      {"encrypted_unlock_key",
       cppcodec::base64_rfc4648::encode(encryptedVerificationKey)},
      {"verification",
       ClientHelpers::makeVerificationRequest(method, userSecret)},
  };
  auto const reply = TC_AWAIT(emit("create user", request));
}

tc::cotask<UserStatusResult> Client::userStatus(
    Trustchain::TrustchainId const& trustchainId,
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

tc::cotask<void> Client::setVerificationMethod(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::UserId const& userId,
    Unlock::Verification const& method,
    Crypto::SymmetricKey userSecret)
{
  nlohmann::json request{
      {"trustchain_id", trustchainId},
      {"user_id", userId},
      {"verification",
       ClientHelpers::makeVerificationRequest(method, userSecret)},
  };
  TC_AWAIT(emit("set verification method", request));
}

tc::cotask<Unlock::FetchAnswer> Client::fetchVerificationKey(
    Unlock::Request const& req)
{
  // DEPRECATED BUT STILL IN USE IN JS INVESTIGATE
  TC_RETURN(TC_AWAIT(emit("get unlock key", req)));
}

tc::cotask<std::string> Client::requestAuthChallenge()
{
  TC_RETURN(TC_AWAIT(emit("request auth challenge", {}))
                .at("challenge")
                .get<std::string>());
}

tc::cotask<std::vector<Unlock::VerificationMethod>> Client::authenticateDevice(
    nlohmann::json const& request)
{
  auto const response = TC_AWAIT(emit("authenticate device", request));
  auto const it = response.find("unlock_methods");
  if (it == response.end())
    TC_RETURN(std::vector<Unlock::VerificationMethod>{});
  TC_RETURN(it.value().get<std::vector<Unlock::VerificationMethod>>());
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
                                  {{"index", lastIndex},
                                   {"extra_users", extra_users},
                                   {"extra_groups", extra_groups}}));
  TC_RETURN(json.get<std::vector<std::string>>());
}

tc::cotask<std::vector<
    std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>>
Client::getPublicProvisionalIdentities(gsl::span<Email const> emails)
{
  if (emails.empty())
    TC_RETURN((std::vector<std::pair<Crypto::PublicSignatureKey,
                                     Crypto::PublicEncryptionKey>>{}));

  nlohmann::json message;
  for (auto const& email : emails)
    message.push_back({{"email", email}});
  auto const result = TC_AWAIT(
      emit("get public provisional identities", nlohmann::json(message)));

  std::vector<
      std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>
      ret;
  ret.reserve(result.size());
  for (auto const& elem : result)
  {
    ret.emplace_back(
        elem.at("SignaturePublicKey").get<Crypto::PublicSignatureKey>(),
        elem.at("EncryptionPublicKey").get<Crypto::PublicEncryptionKey>());
  }
  TC_RETURN(ret);
}

tc::cotask<nonstd::optional<TankerSecretProvisionalIdentity>>
Client::getProvisionalIdentityKeys(Unlock::Verification const& verification,
                                   Crypto::SymmetricKey const& userSecret)
{
  nlohmann::json body = {
      {"verification",
       ClientHelpers::makeVerificationRequest(verification, userSecret)}};
  auto const json = TC_AWAIT(emit("get provisional identity", body));

  if (json.empty())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN(nonstd::make_optional(TankerSecretProvisionalIdentity{
      {json.at("EncryptionPublicKey").get<Crypto::PublicEncryptionKey>(),
       json.at("EncryptionPrivateKey").get<Crypto::PrivateEncryptionKey>()},
      {json.at("SignaturePublicKey").get<Crypto::PublicSignatureKey>(),
       json.at("SignaturePrivateKey").get<Crypto::PrivateSignatureKey>()}}));
}

tc::cotask<nonstd::optional<TankerSecretProvisionalIdentity>>
Client::getVerifiedProvisionalIdentityKeys(Crypto::Hash const& hashedEmail)
{
  nlohmann::json body = {
      {"verification_method", {{"type", "email"}, {"email", hashedEmail}}}};
  auto const json = TC_AWAIT(emit("get verified provisional identity", body));

  if (json.empty())
    TC_RETURN(nonstd::nullopt);

  TC_RETURN(nonstd::make_optional(TankerSecretProvisionalIdentity{
      {json.at("EncryptionPublicKey").get<Crypto::PublicEncryptionKey>(),
       json.at("EncryptionPrivateKey").get<Crypto::PrivateEncryptionKey>()},
      {json.at("SignaturePublicKey").get<Crypto::PublicSignatureKey>(),
       json.at("SignaturePrivateKey").get<Crypto::PrivateSignatureKey>()}}));
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
    throw ServerError{eventName, statusCode, code, message};
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

nlohmann::json ClientHelpers::makeVerificationRequest(
    Unlock::Verification const& verification,
    Crypto::SymmetricKey const& userSecret)
{
  nlohmann::json request;
  if (auto const verif =
          mpark::get_if<Unlock::EmailVerification>(&verification))
  {
    request["email"] = Crypto::generichash(
        gsl::make_span(verif->email).as_span<std::uint8_t const>());
    request["encrypted_email"] =
        cppcodec::base64_rfc4648::encode(Crypto::encryptAead(
            userSecret, gsl::make_span(verif->email).as_span<uint8_t const>()));
    request["verification_code"] = verif->verificationCode;
  }
  else if (auto const pass = mpark::get_if<Password>(&verification))
  {
    request["passphrase"] = cppcodec::base64_rfc4648::encode(
        Crypto::generichash(gsl::make_span(*pass).as_span<uint8_t const>()));
  }
  else if (!mpark::holds_alternative<VerificationKey>(verification))
    // as we return an empty json for verification key the only thing to do if
    // it is NOT a verificationKey is to throw
    throw Errors::AssertionError("unsupported verification request");
  return request;
}

} // Tanker
