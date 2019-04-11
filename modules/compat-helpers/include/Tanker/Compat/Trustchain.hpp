#pragma once

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Types/SUserId.hpp>
#include <Tanker/Types/TrustchainId.hpp>

#include <optional.hpp>

#include <memory>
#include <string>

namespace Tanker
{
namespace Compat
{
struct User
{
  Tanker::SUserId suserId;
  std::string identity;
  nonstd::optional<std::string> user_token;
};

void to_json(nlohmann::json& j, User const& state);
void from_json(nlohmann::json const& j, User& state);

struct TrustchainConfig
{
  std::string url;
  Tanker::TrustchainId trustchainId;
  Tanker::Crypto::PrivateSignatureKey privateKey;
};

void to_json(nlohmann::json& j, TrustchainConfig const& state);
void from_json(nlohmann::json const& j, TrustchainConfig& state);

class TrustchainFactory;

class Trustchain
{
public:
  using Deleter = std::function<void(Trustchain*)>;
  using Ptr = std::unique_ptr<Trustchain, Deleter>;
  using Props = std::tuple<std::string,
                           Tanker::TrustchainId,
                           Tanker::Crypto::SignatureKeyPair>;
  friend TrustchainFactory;

private:
  Props _props;

public:
  Trustchain(Trustchain&&) = default;
  Trustchain& operator=(Trustchain&&) = default;

  static void deleter(Trustchain*);
  static Ptr make(TrustchainConfig config,
                  Deleter deleter = &Trustchain::deleter);
  static Ptr make(Props config, Deleter deleter = &Trustchain::deleter);

  Tanker::TrustchainId const& id() const;
  std::string const& url() const;
  Tanker::Crypto::SignatureKeyPair const& keyPair() const;

  User createUser() const;
  TrustchainConfig toConfig() const;

private:
  Trustchain(Props props);
  Trustchain();
};
}
}
