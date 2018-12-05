#include <Tanker/UserToken/UserToken.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Types/UserId.hpp>
#include <Tanker/UserToken/Delegation.hpp>

#include <nlohmann/json.hpp>

#include <array>
#include <memory>
#include <stdexcept>
#include <tuple>

namespace Tanker
{
namespace UserToken
{
std::vector<uint8_t> userSecretHash(gsl::span<uint8_t const> secretRand,
                                    UserId const& userId)
{
  if (secretRand.size() != USER_SECRET_SIZE - 1)
    throw std::invalid_argument("secretRand array has bad size");
  std::vector<uint8_t> input;
  input.insert(input.end(), secretRand.begin(), secretRand.end());
  input.insert(input.end(), userId.begin(), userId.end());
  return Tanker::Crypto::generichash16(input);
}

Crypto::SymmetricKey generateUserSecret(UserId const& userId)
{
  Crypto::SymmetricKey random;
  auto sp = gsl::make_span(random.data(), random.size() - 1);
  Crypto::randomFill(sp);
  auto check = userSecretHash(sp, userId);
  random.back() = check[0];
  return random;
}

std::string generateUserToken(std::string const& trustchainIdString,
                              std::string const& trustchainPrivateKey,
                              SUserId const& userId)
{
  if (userId.empty())
    throw std::invalid_argument("Empty userId");
  if (trustchainIdString.empty())
    throw std::invalid_argument("Empty trustchainId");
  if (trustchainPrivateKey.empty())
    throw std::invalid_argument("Empty trustchainPrivateKey");

  auto const trustchainId = base64::decode<UserId>(trustchainIdString);
  return generateUserToken(
      base64::decode<Tanker::Crypto::PrivateSignatureKey>(trustchainPrivateKey),
      Tanker::obfuscateUserId(userId, trustchainId));
}

std::string generateUserToken(
    Tanker::Crypto::PrivateSignatureKey const& trustchainPrivateKey,
    UserId const& obfuscatedUserId)
{
  UserToken userToken{};
  userToken.delegation = makeDelegation(obfuscatedUserId, trustchainPrivateKey);
  userToken.userSecret = generateUserSecret(obfuscatedUserId);

  return base64::encode(nlohmann::json(userToken).dump());
}

void from_json(nlohmann::json const& j, UserToken& result)
{
  j.at("user_id").get_to(result.delegation.userId);
  j.at("ephemeral_public_signature_key")
      .get_to(result.delegation.ephemeralKeyPair.publicKey);
  j.at("ephemeral_private_signature_key")
      .get_to(result.delegation.ephemeralKeyPair.privateKey);
  j.at("delegation_signature").get_to(result.delegation.signature);
  j.at("user_secret").get_to(result.userSecret);
}

void to_json(nlohmann::json& j, UserToken const& result)
{
  j["user_id"] = result.delegation.userId;
  j["ephemeral_public_signature_key"] =
      result.delegation.ephemeralKeyPair.publicKey;
  j["ephemeral_private_signature_key"] =
      result.delegation.ephemeralKeyPair.privateKey;
  j["delegation_signature"] = result.delegation.signature;
  j["user_secret"] = result.userSecret;
}

UserToken extract(std::string const& token)
{
  return nlohmann::json::parse(base64::decode(token)).get<UserToken>();
}

static_assert(sizeof(UserToken) == sizeof(Tanker::Crypto::SignatureKeyPair) +
                                       sizeof(Tanker::Crypto::Hash) * 2 +
                                       sizeof(Tanker::Crypto::Signature),
              "Update Operator ==");

bool operator==(UserToken const& lhs, UserToken const& rhs) noexcept
{
  return std::tie(lhs.delegation, lhs.userSecret) ==
         std::tie(rhs.delegation, rhs.userSecret);
}

bool operator!=(UserToken const& lhs, UserToken const& rhs) noexcept
{
  return !(lhs == rhs);
}
}
}
