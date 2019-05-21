#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/VerificationKey.hpp>
#include <Tanker/Unlock/Verification.hpp>

#include <nlohmann/json_fwd.hpp>

#include <optional.hpp>

namespace Tanker
{
namespace Unlock
{
struct Claims
{
  nonstd::optional<Email> email;
  nonstd::optional<Crypto::Hash> password;
  nonstd::optional<std::vector<uint8_t>> verificationKey;

public:
  Claims(Claims const&) = default;
  Claims(Claims&&) = default;
  Claims() = default;
  Claims& operator=(Claims const&) = default;
  Claims& operator=(Claims&&) = default;

  Claims(Verification const& method, Crypto::SymmetricKey const& userSecret);

  std::size_t size() const;
  std::vector<uint8_t> signData() const;
  VerificationKey getVerificationKey(Crypto::SymmetricKey const& key) const;
};

void from_json(nlohmann::json const& j, Claims& m);

void to_json(nlohmann::json&, Claims const& m);
}
}
