#include <Tanker/Unlock/Verification.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/Errors/AssertionError.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Unlock
{
void to_json(nlohmann::json& j, VerificationMethod const& method)
{
  if (method.holds_alternative<Passphrase>())
    j.push_back({{"type", "password"}});
  else if (method.holds_alternative<VerificationKey>())
    j.push_back({{"type", "verificationKey"}});
  else if (auto const email = method.get_if<Email>())
    j.push_back({{"type", "email"},
                 {"email", cppcodec::base64_rfc4648::encode(*email)}});
  else
    throw Errors::AssertionError("use of an outdated sdk");
}

void from_json(nlohmann::json const& j, VerificationMethod& m)
{
  auto const value = j.at("type").get<std::string>();
  if (value == "password")
    m = Passphrase{};
  else if (value == "verificationKey")
    m = VerificationKey{};
  else if (value == "email")
  {
    auto const email = j.at("encrypted_email").get<std::string>();
    auto const decodedEmail = cppcodec::base64_rfc4648::decode(email);
    m = Email{decodedEmail.begin(), decodedEmail.end()};
  }
  else
    throw Errors::AssertionError("use of an outdated sdk");
}
}
}
