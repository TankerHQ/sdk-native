#include "OidcHelpers.hpp"

#include <Tanker/Crypto/Crypto.hpp>

#include <Helpers/Config.hpp>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <mgs/base64url.hpp>
#include <nlohmann/json.hpp>

namespace Tanker
{
std::string oidcProviderId(Tanker::Trustchain::TrustchainId const& appId,
                           std::string const& issuer,
                           std::string const& clientId)
{
  auto normalizedIssuer = issuer;
  if (issuer == "accounts.google.com")
    normalizedIssuer = "https://accounts.google.com";

  auto hashedIssuer = Crypto::generichash(gsl::make_span(normalizedIssuer).as_span<std::uint8_t const>());
  auto hashedClientId = Crypto::generichash(gsl::make_span(clientId).as_span<std::uint8_t const>());

  std::vector<std::uint8_t> toHash;
  toHash.insert(toHash.end(), appId.begin(), appId.end());
  toHash.insert(toHash.end(), hashedIssuer.begin(), hashedIssuer.end());
  toHash.insert(toHash.end(), hashedClientId.begin(), hashedClientId.end());

  return mgs::base64url_nopad::encode(Crypto::generichash(gsl::make_span(toHash).as_span<std::uint8_t const>()));
}

std::string getOidcSubject(OidcIdToken const& oidcIdToken)
{
  std::vector<std::string> res;
  boost::algorithm::split(res, oidcIdToken.token, boost::algorithm::is_any_of("."));

  auto const jwtPayload = mgs::base64url_nopad::decode(res[1]);

  auto const j = nlohmann::json::parse(jwtPayload);
  return j.at("sub").get<std::string>();
}
}
