#include <Tanker/Compat/Trustchain.hpp>

#include <Tanker/Crypto/JsonFormat.hpp>
#include <Tanker/Types/TrustchainId.hpp>
#include <Tanker/UserToken/UserToken.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Compat
{

void to_json(nlohmann::json& j, User const& user)
{
  j["suser_id"] = user.suserId;
  j["user_token"] = user.user_token;
}

void from_json(nlohmann::json const& j, User& user)
{
  j.at("suser_id").get_to(user.suserId);
  j.at("user_token").get_to(user.user_token);
}

void to_json(nlohmann::json& j, TrustchainConfig const& config)
{
  j["trustchainId"] = config.trustchainId;
  j["url"] = config.url;
  j["trustchainPrivateKey"] = config.privateKey;
}

void from_json(nlohmann::json const& j, TrustchainConfig& config)
{
  j.at("trustchainId").get_to(config.trustchainId);
  j.at("url").get_to(config.url);
  j.at("trustchainPrivateKey").get_to(config.privateKey);
}

Trustchain::Trustchain(Props props) : _props(std::move(props))
{
}

Tanker::TrustchainId const& Trustchain::id() const
{
  return std::get<Tanker::TrustchainId>(_props);
}

std::string const& Trustchain::url() const
{
  return std::get<std::string>(_props);
}

Tanker::Crypto::SignatureKeyPair const& Trustchain::keyPair() const
{
  return std::get<Tanker::Crypto::SignatureKeyPair>(_props);
}

User Trustchain::createUser() const
{
  auto userId = Tanker::UserId{};
  Crypto::randomFill(userId);
  auto const suserId = Tanker::SUserId{base64::encode(userId)};
  return User{suserId,
              Tanker::UserToken::generateUserToken(
                  Tanker::base64::encode(id()),
                  Tanker::base64::encode(keyPair().privateKey),
                  suserId)};
}

TrustchainConfig Trustchain::toConfig() const
{
  return {url(), id(), keyPair().privateKey};
}

void Trustchain::deleter(Trustchain* tc)
{
  delete tc;
}

Trustchain::Ptr Trustchain::make(TrustchainConfig config, Deleter deleter)
{
  return Ptr(
      new Trustchain({std::move(config.url),
                      config.trustchainId,
                      Tanker::Crypto::makeSignatureKeyPair(config.privateKey)}),
      deleter);
}

Trustchain::Ptr Trustchain::make(Props props, Deleter deleter)
{
  return Ptr(new Trustchain(std::move(props)), &Trustchain::deleter);
}
}
}
