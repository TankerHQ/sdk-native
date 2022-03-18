#pragma once

#include <Tanker/Functional/Provisional.hpp>
#include <Tanker/Functional/User.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <nlohmann/json_fwd.hpp>

#include <memory>
#include <string>

namespace Tanker
{
namespace Functional
{
struct TrustchainConfig
{
  std::string url;
  Tanker::Trustchain::TrustchainId id;
  std::string authToken;
  Crypto::PrivateSignatureKey privateKey;
};

void to_json(nlohmann::json& j, TrustchainConfig const& state);
void from_json(nlohmann::json const& j, TrustchainConfig& state);

class TrustchainFactory;

class Trustchain
{
public:
  using Ptr = std::unique_ptr<Trustchain>;
  friend TrustchainFactory;

  std::string url;
  Tanker::Trustchain::TrustchainId id;
  std::string authToken;
  Crypto::SignatureKeyPair keyPair;

  static Ptr make(TrustchainConfig const& config);
  static Ptr make(std::string url,
                  Tanker::Trustchain::TrustchainId id,
                  std::string authToken,
                  Crypto::PrivateSignatureKey privateSignatureKey);

  Trustchain(TrustchainConfig const& config);
  Trustchain(std::string url,
             Tanker::Trustchain::TrustchainId id,
             std::string authToken,
             Crypto::PrivateSignatureKey privateSignatureKey);
  Trustchain(Trustchain&&) = default;
  Trustchain& operator=(Trustchain&&) = default;

  User makeUser();
  AppProvisionalUser makeEmailProvisionalUser();
  AppProvisionalUser makePhoneNumberProvisionalUser();

  TrustchainConfig toConfig() const;

private:
  Trustchain();
};
}
}
