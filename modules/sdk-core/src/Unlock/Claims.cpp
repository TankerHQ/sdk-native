#include <Tanker/Unlock/Claims.hpp>

#include <Tanker/Crypto/Crypto.hpp>

#include <nlohmann/json.hpp>

#include <iterator>

namespace Tanker
{
namespace Unlock
{

Claims::Claims(UpdateOptions const& lockOptions,
               Crypto::SymmetricKey const& userSecret)
{
  this->email = lockOptions.get<Email>();
  if (auto const opt_password = lockOptions.get<Password>())
    password = Crypto::generichash(
        gsl::make_span(*opt_password).as_span<uint8_t const>());
  if (auto const opt_unlockKey = lockOptions.get<UnlockKey>())
    this->unlockKey = Crypto::encryptAead(
        userSecret, gsl::make_span(*opt_unlockKey).as_span<uint8_t const>());
}

void from_json(nlohmann::json const& j, Claims& c)
{
  if (j.count("email"))
    c.email = base64::decode<Email>(j.at("email").get<Email>());
  if (j.count("password"))
    c.password = j.at("password").get<Crypto::Hash>();
  if (j.count("unlock_key"))
    c.unlockKey = base64::decode(j.at("unlock_key").get<std::string>());
}

void to_json(nlohmann::json& j, Claims const& c)
{
  if (c.email.has_value())
    j["email"] = base64::encode(c.email.value());
  if (c.password.has_value())
    j["password"] = c.password.value();
  if (c.unlockKey.has_value())
    j["unlock_key"] = base64::encode(c.unlockKey.value());
}

std::size_t Claims::size() const
{
  auto const giveMeSize = [](auto&& p) {
    auto ret = std::size_t{0};
    if (p.has_value())
      ret = p->size();
    return ret;
  };
  return giveMeSize(email) + giveMeSize(password) + giveMeSize(unlockKey);
}

std::vector<uint8_t> Claims::signData() const
{
  auto const appendMe = [](auto const& p, auto&& outputIt) {
    if (p.has_value())
    {
      auto const& value = p.value();
      std::copy(value.begin(), value.end(), outputIt);
    }
  };

  std::vector<uint8_t> toSign;
  toSign.reserve(size());
  appendMe(email, std::back_inserter(toSign));
  appendMe(password, std::back_inserter(toSign));
  appendMe(unlockKey, std::back_inserter(toSign));
  return toSign;
}

UnlockKey Claims::getUnlockKey(Crypto::SymmetricKey const& key) const
{
  auto const binKey = Crypto::decryptAead(key, unlockKey.value());
  return {begin(binKey), end(binKey)};
}
}
}
