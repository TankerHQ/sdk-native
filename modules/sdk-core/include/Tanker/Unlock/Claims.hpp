#pragma once

#include <Tanker/Crypto/SymmetricKey.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Unlock/Options.hpp>

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
  nonstd::optional<std::vector<uint8_t>> unlockKey;

public:
  Claims(Claims const&) = default;
  Claims(Claims&&) = default;
  Claims() = default;
  Claims& operator=(Claims const&) = default;
  Claims& operator=(Claims&&) = default;

  Claims(UpdateOptions const& lockOptions,
         Crypto::SymmetricKey const& userSecret);

  std::size_t size() const;
  std::vector<uint8_t> signData() const;
  UnlockKey getUnlockKey(Crypto::SymmetricKey const& key) const;
};

void from_json(nlohmann::json const& j, Claims& m);

void to_json(nlohmann::json&, Claims const& m);
}
}
