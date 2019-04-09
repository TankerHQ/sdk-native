#include <Tanker/Unlock/Messages.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/KeyFormat.hpp>
#include <Tanker/Crypto/base64.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/Unlock/Claims.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <gsl-lite.hpp>
#include <nlohmann/json.hpp>

#include <iterator>
#include <string>

namespace Tanker
{
namespace Unlock
{

void to_json(nlohmann::json& j, Request const& m)
{
  j["trustchain_id"] = m.trustchainId;
  j["user_id"] = m.userId;
  j["type"] = to_string(m.type);
  j["value"] = cppcodec::base64_rfc4648::encode(m.value);
}

void to_json(nlohmann::json& j, FetchAnswer const& m)
{
  j["encrypted_unlock_key"] =
      cppcodec::base64_rfc4648::encode(m.encryptedUnlockKey);
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
  f.encryptedUnlockKey = cppcodec::base64_rfc4648::decode<std::vector<uint8_t>>(
      j.at("encrypted_unlock_key").get<std::string>());
}

void from_json(nlohmann::json const& j, Message& m)
{
  m.trustchainId = j.at("trustchain_id").get<Crypto::Hash>();
  m.deviceId = j.at("device_id").get<Crypto::Hash>();
  m.claims = j.at("claims").get<Claims>();
  m.signature = j.at("signature").get<Crypto::Signature>();
}

Request::Request(TrustchainId const& trustchainId,
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
    auto const code = safeBase64Unpadded::decode(*rawcode);
    value.assign(code.begin(), code.end());
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
  throw std::runtime_error("assertion failure: unhandled method type");
}

FetchAnswer::FetchAnswer(Crypto::SymmetricKey const& userSecret,
                         UnlockKey const& unlockKey)
  : encryptedUnlockKey(Crypto::encryptAead(
        userSecret, gsl::make_span(unlockKey).as_span<uint8_t const>()))
{
}

UnlockKey FetchAnswer::getUnlockKey(Crypto::SymmetricKey const& key) const
{
  auto const binKey = Crypto::decryptAead(key, this->encryptedUnlockKey);
  return {begin(binKey), end(binKey)};
}

Message::Message(TrustchainId const& trustchainId,
                 DeviceId const& deviceId,
                 UpdateOptions const& lockOptions,
                 Crypto::SymmetricKey const& userSecret,
                 Crypto::PrivateSignatureKey const& privateSignatureKey)
  : trustchainId(trustchainId),
    deviceId(deviceId),
    claims{lockOptions, userSecret}
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
