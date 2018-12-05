#pragma once

#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Types/DeviceId.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/Unlock/Claims.hpp>
#include <Tanker/Unlock/DeviceLocker.hpp>
#include <Tanker/Unlock/Options.hpp>

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <vector>

namespace Tanker
{
namespace Unlock
{

struct Request
{
  TrustchainId trustchainId;
  UserId userId;
  enum Type
  {
    Password,
    VerificationCode,
    Last,
  } type;
  std::vector<uint8_t> value;

  Request() = default;
  Request(TrustchainId const& trustchainId,
          UserId const& userId,
          DeviceLocker const& locker);
};

std::string to_string(Request::Type type);

void to_json(nlohmann::json&, Request const& m);

struct FetchAnswer
{
  std::vector<uint8_t> encryptedUnlockKey;

  FetchAnswer() = default;
  FetchAnswer(Crypto::SymmetricKey const& key, UnlockKey const& unlockKey);

  UnlockKey getUnlockKey(Crypto::SymmetricKey const& key) const;
};
void from_json(nlohmann::json const& j, FetchAnswer& m);

void to_json(nlohmann::json&, FetchAnswer const& m);

struct Message
{
  TrustchainId trustchainId;
  DeviceId deviceId;
  Claims claims;
  Crypto::Signature signature;

  Message() = default;
  Message(TrustchainId const& trustchainId,
          DeviceId const& deviceId,
          UpdateOptions const& lockOptions,
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
