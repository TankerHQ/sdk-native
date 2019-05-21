#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Claims.hpp>
#include <Tanker/Unlock/DeviceLocker.hpp>
#include <Tanker/Unlock/Verification.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <vector>

namespace Tanker
{
namespace Unlock
{

struct Request
{
  Trustchain::TrustchainId trustchainId;
  Trustchain::UserId userId;
  enum Type
  {
    Password,
    VerificationCode,
    Last,
  } type;
  std::vector<uint8_t> value;

  Request() = default;
  Request(Trustchain::TrustchainId const& trustchainId,
          Trustchain::UserId const& userId,
          DeviceLocker const& locker);
};

std::string to_string(Request::Type type);

void to_json(nlohmann::json&, Request const& m);

struct FetchAnswer
{
  std::vector<uint8_t> encryptedVerificationKey;

  FetchAnswer() = default;
  FetchAnswer(Crypto::SymmetricKey const& key,
              VerificationKey const& verificationKey);

  VerificationKey getVerificationKey(Crypto::SymmetricKey const& key) const;
};
void from_json(nlohmann::json const& j, FetchAnswer& m);

void to_json(nlohmann::json&, FetchAnswer const& m);

struct Message
{
  Trustchain::TrustchainId trustchainId;
  Trustchain::DeviceId deviceId;
  Claims claims;
  Crypto::Signature signature;

  Message() = default;
  Message(Trustchain::TrustchainId const& trustchainId,
          Trustchain::DeviceId const& deviceId,
          Verification const& verificationMethod,
          Crypto::SymmetricKey const& key,
          Crypto::PrivateSignatureKey const& privateSignatureKey);

  std::size_t size() const;
  std::vector<uint8_t> signData() const;
  void sign(Crypto::PrivateSignatureKey const& key);
  friend void from_json(nlohmann::json const& j, Message& m);
};

void to_json(nlohmann::json&, Message const& m);
}
}
