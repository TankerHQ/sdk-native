#include <Tanker/Unlock/Messages.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/Passphrase.hpp>
#include <Tanker/Types/VerificationKey.hpp>

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
void to_json(nlohmann::json& j, FetchAnswer const& m)
{
  j["encrypted_verification_key"] =
      cppcodec::base64_rfc4648::encode(m.encryptedVerificationKey);
}

void from_json(nlohmann::json const& j, FetchAnswer& f)
{
  f.encryptedVerificationKey =
      cppcodec::base64_rfc4648::decode<std::vector<uint8_t>>(
          j.at("encrypted_verification_key").get<std::string>());
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
}
}
