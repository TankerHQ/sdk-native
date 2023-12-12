#pragma once

#include <Tanker/Format/StringView.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Types/OidcIdToken.hpp>

#include <nlohmann/json_fwd.hpp>
#include <tconcurrent/coroutine.hpp>

#include <Helpers/Config.hpp>

#include <string>

namespace Tanker
{
tc::cotask<std::string> checkSessionToken(Trustchain::TrustchainId appId,
                                          std::string const& verificationApiToken,
                                          std::string const& publicIdentity,
                                          std::string const& sessionToken,
                                          nlohmann::json const& allowedMethods);

tc::cotask<std::string> checkSessionToken(Trustchain::TrustchainId appId,
                                          std::string const& verificationApiToken,
                                          std::string const& publicIdentity,
                                          std::string const& sessionToken,
                                          std::string const& allowedMethod);

tc::cotask<OidcIdToken> getOidcToken(TestConstants::OidcConfig& oidcConfig, std::string userName);
}
