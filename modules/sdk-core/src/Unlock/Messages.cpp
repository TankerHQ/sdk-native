#include <Tanker/Unlock/Messages.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Claims.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <cppcodec/base64_url_unpadded.hpp>
#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>

#include <iterator>
#include <string>

using Tanker::Trustchain::UserId;

namespace Tanker
{
namespace Unlock
{

void to_json(nlohmann::json& j, Request const& m)
{
  j["trustchain_id"] = m.trustchainId;
  j["user_id"] = m.userId;
  j["type"] = to_string(m.type);
  if (m.type == Request::Type::VerificationCode)
    j["value"] = std::string(m.value.begin(), m.value.end());
  else
    j["value"] = cppcodec::base64_rfc4648::encode(m.value);
}

void to_json(nlohmann::json& j, FetchAnswer const& m)
{
  j["encrypted_unlock_key"] =
      cppcodec::base64_rfc4648::encode(m.encryptedVerificationKey);
}

void to_json(nlohmann::json& j, Message const& m)
{
  j["trustchain_id"] = m.trustchainId;
  j["device_id"] = m.deviceId;
  j["claims"] = m.claims;
  j["signature"] = m.signature;
}

void from_json(nlohmann::json const& j, FetchAnswer& f)
{
  f.encryptedVerificationKey =
      cppcodec::base64_rfc4648::decode<std::vector<uint8_t>>(
          j.at("encrypted_unlock_key").get<std::string>());
}

void from_json(nlohmann::json const& j, Message& m)
{
  m.trustchainId = j.at("trustchain_id").get<Trustchain::TrustchainId>();
  m.deviceId = j.at("device_id").get<Trustchain::DeviceId>();
  m.claims = j.at("claims").get<Claims>();
  m.signature = j.at("signature").get<Crypto::Signature>();
}

Request::Request(Trustchain::TrustchainId const& trustchainId,
                 UserId const& userId,
                 DeviceLocker const& locker)
  : trustchainId(trustchainId), userId(userId)
{
  if (auto const pass = mpark::get_if<Password>(&locker))
  {
    auto const hash =
        Crypto::generichash(gsl::make_span(*pass).as_span<uint8_t const>());
    value.assign(hash.begin(), hash.end());
    type = Type::Password;
  }
  else if (auto rawcode = mpark::get_if<VerificationCode>(&locker))
  {
    value.assign(rawcode->begin(), rawcode->end());
    type = Type::VerificationCode;
  }
}

std::string to_string(Request::Type type)
{
  switch (type)
  {
  case Request::Type::Password:
    return "password";
  case Request::Type::VerificationCode:
    return "verification_code";
  case Request::Type::Last:
    break;
  }
  throw Errors::AssertionError(
      fmt::format("unhandled method type: {}", static_cast<int>(type)));
}

FetchAnswer::FetchAnswer(Crypto::SymmetricKey const& userSecret,
                         VerificationKey const& verificationKey)
  : encryptedVerificationKey(Crypto::encryptAead(
        userSecret, gsl::make_span(verificationKey).as_span<uint8_t const>()))
{
}

VerificationKey FetchAnswer::getVerificationKey(
    Crypto::SymmetricKey const& key) const
{
  auto const binKey = Crypto::decryptAead(key, this->encryptedVerificationKey);
  return {begin(binKey), end(binKey)};
}

Message::Message(Trustchain::TrustchainId const& trustchainId,
                 Trustchain::DeviceId const& deviceId,
                 Verification const& verificationMethod,
                 Crypto::SymmetricKey const& userSecret,
                 Crypto::PrivateSignatureKey const& privateSignatureKey)
  : trustchainId(trustchainId),
    deviceId(deviceId),
    claims{verificationMethod, userSecret}
{
  sign(privateSignatureKey);
}

std::size_t Message::size() const
{
  return trustchainId.size() + deviceId.size() + claims.size();
}

std::vector<uint8_t> Message::signData() const
{
  std::vector<uint8_t> toSign;
  toSign.reserve(size());
  toSign.insert(toSign.end(), trustchainId.begin(), trustchainId.end());
  toSign.insert(toSign.end(), deviceId.begin(), deviceId.end());

  auto const claimsSignData = claims.signData();
  toSign.insert(toSign.end(), claimsSignData.begin(), claimsSignData.end());
  return toSign;
}

void Message::sign(Crypto::PrivateSignatureKey const& privateSignatureKey)
{
  this->signature = Crypto::sign(signData(), privateSignatureKey);
}
}
}
