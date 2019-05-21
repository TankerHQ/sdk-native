#include <Tanker/Unlock/Claims.hpp>

#include <Tanker/Crypto/Crypto.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

#include <iterator>

namespace Tanker
{
namespace Unlock
{

Claims::Claims(Verification const& method,
               Crypto::SymmetricKey const& userSecret)
{
  if (auto const emailVerification =
          mpark::get_if<Unlock::EmailVerification>(&method))
    this->email = emailVerification->email;
  else if (auto const password = mpark::get_if<Password>(&method))
    this->password =
        Crypto::generichash(gsl::make_span(*password).as_span<uint8_t const>());
  else if (auto const verificationKey = mpark::get_if<VerificationKey>(&method))
    throw std::runtime_error(
        "assertion failure, not supposed to have a verificationKey");
}

void from_json(nlohmann::json const& j, Claims& c)
{
  if (j.count("email"))
  {
    c.email =
        cppcodec::base64_rfc4648::decode<Email>(j.at("email").get<Email>());
  }
  if (j.count("password"))
    c.password = j.at("password").get<Crypto::Hash>();
  if (j.count("unlock_key"))
  {
    c.verificationKey =
        cppcodec::base64_rfc4648::decode(j.at("unlock_key").get<std::string>());
  }
}

void to_json(nlohmann::json& j, Claims const& c)
{
  if (c.email.has_value())
    j["email"] = cppcodec::base64_rfc4648::encode(c.email.value());
  if (c.password.has_value())
    j["password"] = c.password.value();
  if (c.verificationKey.has_value())
    j["unlock_key"] =
        cppcodec::base64_rfc4648::encode(c.verificationKey.value());
}

std::size_t Claims::size() const
{
  auto const giveMeSize = [](auto&& p) {
    auto ret = std::size_t{0};
    if (p.has_value())
      ret = p->size();
    return ret;
  };
  return giveMeSize(email) + giveMeSize(password) + giveMeSize(verificationKey);
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
  appendMe(verificationKey, std::back_inserter(toSign));
  return toSign;
}

VerificationKey Claims::getVerificationKey(
    Crypto::SymmetricKey const& key) const
{
  auto const binKey = Crypto::decryptAead(key, verificationKey.value());
  return {begin(binKey), end(binKey)};
}
}
}
