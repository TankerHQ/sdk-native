#pragma once

#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Types/OidcIdToken.hpp>

#include <string>

namespace Tanker
{
std::string oidcProviderId(Tanker::Trustchain::TrustchainId const& appId,
                           std::string const& issuer,
                           std::string const& clientId);
std::string getOidcSubject(OidcIdToken const& oidcIdToken);
}
