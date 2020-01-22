#pragma once

#include <Tanker/Crypto/Hash.hpp>
#include <Tanker/Trustchain/HashedPassphrase.hpp>
#include <Tanker/Types/VerificationCode.hpp>
#include <Tanker/Unlock/Verification.hpp>

#include <boost/variant2/variant.hpp>

#include <nlohmann/json_fwd.hpp>

#include <tuple>
#include <vector>

namespace Tanker::Unlock
{
using EncryptedEmailVerification =
    std::tuple<Crypto::Hash, std::vector<std::uint8_t>, VerificationCode>;

using Request = boost::variant2::variant<VerificationKey,
                                         EncryptedEmailVerification,
                                         Trustchain::HashedPassphrase,
                                         OidcIdToken>;
void to_json(nlohmann::json&, Request const&);

Request makeRequest(Unlock::Verification const& verification,
                    Crypto::SymmetricKey const& userSecret);
}

namespace nlohmann
{
template <typename SFINAE>
struct adl_serializer<Tanker::Unlock::Request, SFINAE>
{
  static void to_json(nlohmann::json& j,
                      Tanker::Unlock::Request const& request);

  static void from_json(nlohmann::json const& j,
                        Tanker::Unlock::Request& request) = delete;
};
}