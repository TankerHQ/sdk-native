#pragma once

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

enum class UserType
{
  Cached,
  New,
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
                  Crypto::SignatureKeyPair keypair);

  Trustchain(TrustchainConfig const& config);
  Trustchain(std::string url,
             Tanker::Trustchain::TrustchainId id,
             Crypto::SignatureKeyPair keypair);
  Trustchain(Trustchain&&) = default;
  Trustchain& operator=(Trustchain&&) = default;

  void reuseCache();

  User makeUser(UserType = UserType::Cached);

  TrustchainConfig toConfig() const;

private:
  Trustchain();

  uint32_t _currentUser = 0;
  std::vector<User> _cachedUsers;
};
}
}
