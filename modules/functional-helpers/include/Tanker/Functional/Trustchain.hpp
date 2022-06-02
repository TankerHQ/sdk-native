#pragma once

#include <Helpers/Config.hpp>
#include <Tanker/Admin/Client.hpp>
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
  Crypto::PrivateSignatureKey privateKey;
};

void to_json(nlohmann::json& j, TrustchainConfig const& state);
void from_json(nlohmann::json const& j, TrustchainConfig& state);

class TrustchainFactory;

enum class ProvisionalUserType
{
  Email,
  PhoneNumber,
};

class Trustchain
{
public:
  using Ptr = std::unique_ptr<Trustchain>;
  friend TrustchainFactory;

  std::string url;
  Tanker::Trustchain::TrustchainId id;
  Crypto::SignatureKeyPair keyPair;

  static Ptr make(TrustchainConfig const& config);
  static Ptr make(std::string url,
                  Tanker::Trustchain::TrustchainId id,
                  Crypto::PrivateSignatureKey privateSignatureKey);

  Trustchain(TrustchainConfig const& config);
  Trustchain(std::string url,
             Tanker::Trustchain::TrustchainId id,
             Crypto::PrivateSignatureKey privateSignatureKey);
  Trustchain(Trustchain&&) = default;
  Trustchain& operator=(Trustchain&&) = default;

  User makeUser();
  AppProvisionalUser makeProvisionalUser(ProvisionalUserType type);
  AppProvisionalUser makeEmailProvisionalUser();
  AppProvisionalUser makePhoneNumberProvisionalUser();

  template <typename T>
  tc::cotask<VerificationCode> getVerificationCode(T&& emailOrPhone)
  {
    TC_RETURN(TC_AWAIT(
        Admin::getVerificationCode(TestConstants::trustchaindUrl(),
                                   id,
                                   TestConstants::verificationApiToken(),
                                   std::forward<T>(emailOrPhone))));
  }
  tc::cotask<void> attachProvisionalIdentity(AsyncCore& session,
                                             AppProvisionalUser const& prov);

  TrustchainConfig toConfig() const;

private:
  Trustchain();
};
}
}
