#pragma once

#include <Tanker/Crypto/PrivateSignatureKey.hpp>
#include <Tanker/Crypto/Signature.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/DeviceLocker.hpp>
#include <Tanker/Unlock/Verification.hpp>

#include <nlohmann/json.hpp>
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
}
}
