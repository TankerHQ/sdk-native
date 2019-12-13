#include <Tanker/Client.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Crypto/SealedPrivateEncryptionKey.hpp>
#include <Tanker/EncryptedUserKey.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/ServerErrc.hpp>
#include <Tanker/Format/Json.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/TankerSecretProvisionalIdentity.hpp>
#include <Tanker/Unlock/Verification.hpp>

#include <Tanker/Tracer/FuncTracer.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>

#include <cppcodec/base64_rfc4648.hpp>

#include <nlohmann/json.hpp>
#include <optional>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <iterator>
#include <utility>

using namespace Tanker::Errors;
using namespace Tanker::Trustchain;

TLOG_CATEGORY(Client);

namespace Tanker
{
namespace
{
template <typename T>
Crypto::Hash hashField(T const& field)
{
  return Crypto::generichash(
      gsl::make_span(field).template as_span<std::uint8_t const>());
}

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
};
}

Client::Client(Network::ConnectionPtr cx, ConnectionHandler connectionHandler)
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
    gsl::span<uint8_t const> userCreation,
    gsl::span<uint8_t const> firstDevice,
    Unlock::Verification const& method,
    Crypto::SymmetricKey userSecret,
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
      {"verification",
       ClientHelpers::makeVerificationRequest(method, userSecret)},
  };
  auto const reply = TC_AWAIT(emit("create user 2", request));
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

tc::cotask<VerificationKey> Client::fetchVerificationKey(
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
  auto const response = TC_AWAIT(emit("get verification key", request));
  auto const verificationKey = Crypto::decryptAead(
      userSecret,
      cppcodec::base64_rfc4648::decode<std::vector<uint8_t>>(
          response.at("encrypted_verification_key").get<std::string>()));
  TC_RETURN(VerificationKey(verificationKey.begin(), verificationKey.end()));
}

tc::cotask<std::vector<Unlock::VerificationMethod>>
Client::fetchVerificationMethods(Trustchain::TrustchainId const& trustchainId,
                                 Trustchain::UserId const& userId,
                                 Crypto::SymmetricKey const& userSecret)
{
  auto const request =
      nlohmann::json{{"trustchain_id", trustchainId}, {"user_id", userId}};

  auto const reply = TC_AWAIT(emit("get verification methods", request));
  auto methods = reply.at("verification_methods")
                     .get<std::vector<Unlock::VerificationMethod>>();
  for (auto& method : methods)
  {
    if (auto encryptedEmail = method.get_if<Email>())
    {
      auto const decryptedEmail = Crypto::decryptAead(
          userSecret,
          gsl::make_span(*encryptedEmail).as_span<std::uint8_t const>());
      method = Email{decryptedEmail.begin(), decryptedEmail.end()};
    }
  }
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

tc::cotask<std::vector<
    std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>>
Client::getPublicProvisionalIdentities(gsl::span<Email const> emails)
{
  if (emails.empty())
    TC_RETURN((std::vector<std::pair<Crypto::PublicSignatureKey,
                                     Crypto::PublicEncryptionKey>>{}));

  nlohmann::json message;
  for (auto const& email : emails)
    message.push_back({{"type", "email"}, {"hashed_email", hashField(email)}});

  auto const result = TC_AWAIT(
      emit("get public provisional identities", nlohmann::json(message)));

  std::vector<
      std::pair<Crypto::PublicSignatureKey, Crypto::PublicEncryptionKey>>
      ret;
  ret.reserve(result.size());
  for (auto const& elem : result)
  {
    ret.emplace_back(
        elem.at("signature_public_key").get<Crypto::PublicSignatureKey>(),
        elem.at("encryption_public_key").get<Crypto::PublicEncryptionKey>());
  }
  TC_RETURN(ret);
}

tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
Client::getProvisionalIdentityKeys(Unlock::Verification const& verification,
                                   Crypto::SymmetricKey const& userSecret)
{
  nlohmann::json body = {
      {"verification",
       ClientHelpers::makeVerificationRequest(verification, userSecret)}};
  auto const json = TC_AWAIT(emit("get provisional identity", body));

  if (json.empty())
    TC_RETURN(std::nullopt);

  TC_RETURN(std::make_optional(TankerSecretProvisionalIdentity{
      {json.at("encryption_public_key").get<Crypto::PublicEncryptionKey>(),
       json.at("encryption_private_key").get<Crypto::PrivateEncryptionKey>()},
      {json.at("signature_public_key").get<Crypto::PublicSignatureKey>(),
       json.at("signature_private_key").get<Crypto::PrivateSignatureKey>()}}));
}

tc::cotask<std::optional<TankerSecretProvisionalIdentity>>
Client::getVerifiedProvisionalIdentityKeys(Crypto::Hash const& hashedEmail)
{
  nlohmann::json body = {{"verification_method",
                          {{"type", "email"}, {"hashed_email", hashedEmail}}}};
  auto const json = TC_AWAIT(emit("get verified provisional identity", body));

  if (json.empty())
    TC_RETURN(std::nullopt);

  TC_RETURN(std::make_optional(TankerSecretProvisionalIdentity{
      {json.at("encryption_public_key").get<Crypto::PublicEncryptionKey>(),
       json.at("encryption_private_key").get<Crypto::PrivateEncryptionKey>()},
      {json.at("signature_public_key").get<Crypto::PublicSignatureKey>(),
       json.at("signature_private_key").get<Crypto::PrivateSignatureKey>()}}));
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

nlohmann::json ClientHelpers::makeVerificationRequest(
    Unlock::Verification const& verification,
    Crypto::SymmetricKey const& userSecret)
{
  nlohmann::json request;
  if (auto const verif =
          boost::variant2::get_if<Unlock::EmailVerification>(&verification))
  {
    request["hashed_email"] = hashField(verif->email);
    request["encrypted_email"] =
        cppcodec::base64_rfc4648::encode(Crypto::encryptAead(
            userSecret, gsl::make_span(verif->email).as_span<uint8_t const>()));
    request["verification_code"] = verif->verificationCode;
  }
  else if (auto const pass = boost::variant2::get_if<Passphrase>(&verification))
    request["hashed_passphrase"] = hashField(*pass);
  else if (auto const oidcIdToken =
               boost::variant2::get_if<OidcIdToken>(&verification))
    request["oidc_id_token"] = oidcIdToken->string();
  else if (!boost::variant2::holds_alternative<VerificationKey>(verification))
    // as we return an empty json for verification key the only thing to do if
    // it is NOT a verificationKey is to throw
    throw Errors::AssertionError("unsupported verification request");
  return request;
}
}
