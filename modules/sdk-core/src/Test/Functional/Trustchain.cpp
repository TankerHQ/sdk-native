#include <Tanker/Test/Functional/Trustchain.hpp>

#include <cppcodec/base64_rfc4648.hpp>

#include <Helpers/Config.hpp>

#include <memory>
#include <string>
#include <utility>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Test
{

void to_json(nlohmann::json& j, TrustchainConfig const& config)
{
  j["trustchainId"] = config.id;
  j["url"] = config.url;
  j["trustchainPrivateKey"] = config.privateKey;
}

void from_json(nlohmann::json const& j, TrustchainConfig& config)
{
  j.at("trustchainId").get_to(config.id);
  j.at("url").get_to(config.url);
  j.at("trustchainPrivateKey").get_to(config.privateKey);
}

Trustchain::Trustchain(std::string url,
                       Tanker::Trustchain::TrustchainId id,
                       Tanker::Crypto::SignatureKeyPair keypair)
  : url(std::move(url)), id(std::move(id)), keyPair(std::move(keypair))
{
}

Trustchain::Trustchain(TrustchainConfig const& config)
  : Trustchain(config.url,
               config.id,
               Tanker::Crypto::makeSignatureKeyPair(config.privateKey))
{
}

void Trustchain::reuseCache()
{
  for (auto& user : _cachedUsers)
    user.reuseCache();
  _currentUser = 0;
}

User Trustchain::makeUser(UserType type)
{
  auto const trustchainIdString = cppcodec::base64_rfc4648::encode(id);
  auto const trustchainPrivateKeyString =
      cppcodec::base64_rfc4648::encode(keyPair.privateKey);

  if (type == UserType::New)
    return User(url, trustchainIdString, trustchainPrivateKeyString);

  if (_currentUser == _cachedUsers.size())
    _cachedUsers.push_back(
        User(url, trustchainIdString, trustchainPrivateKeyString));
  return _cachedUsers[_currentUser++];
}

TrustchainConfig Trustchain::toConfig() const
{
  return {url, id, keyPair.privateKey};
}

Trustchain::Ptr Trustchain::make(TrustchainConfig const& config)
{
  return std::make_unique<Trustchain>(config);
}

Trustchain::Ptr Trustchain::make(std::string url,
                                 Tanker::Trustchain::TrustchainId id,
                                 Tanker::Crypto::SignatureKeyPair keypair)
{
  return std::make_unique<Trustchain>(
      std::move(url), std::move(id), std::move(keypair));
}
}
}
