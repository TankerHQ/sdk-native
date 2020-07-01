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

#include <mgs/base64.hpp>

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
      _taskCanceler.add(tc::async([this]() { _connectionHandler(); }));
  };
}

void Client::start()
{
  FUNC_BEGIN("client connection", Net);
  _cx->connect();
}

void Client::close()
{
  _cx->close();
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
