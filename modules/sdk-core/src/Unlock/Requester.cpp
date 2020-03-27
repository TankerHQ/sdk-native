#include <Tanker/Client.hpp>
#include <Tanker/Unlock/Requester.hpp>

#include <nlohmann/json.hpp>

namespace Tanker::Unlock
{

Requester::Requester(Client* client) : _client(client)
{
}

tc::cotask<void> Requester::setVerificationMethod(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::UserId const& userId,
    Unlock::Request const& request)
{
  nlohmann::json payload{
      {"trustchain_id", trustchainId},
      {"user_id", userId},
      {"verification", request},
  };
  TC_AWAIT(_client->emit("set verification method", payload));
}

tc::cotask<std::vector<std::uint8_t>> Requester::fetchVerificationKey(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::UserId const& userId,
    Unlock::Request const& request)
{
  nlohmann::json payload{
      {"trustchain_id", trustchainId},
      {"user_id", userId},
      {"verification", request},
  };
  auto const response =
      TC_AWAIT(_client->emit("get verification key", payload));
  TC_RETURN(cppcodec::base64_rfc4648::decode<std::vector<uint8_t>>(
      response.at("encrypted_verification_key").get<std::string>()));
}

tc::cotask<std::vector<Unlock::VerificationMethod>>
Requester::fetchVerificationMethods(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::UserId const& userId)
{
  auto const request =
      nlohmann::json{{"trustchain_id", trustchainId}, {"user_id", userId}};

  auto const reply =
      TC_AWAIT(_client->emit("get verification methods", request));
  auto methods = reply.at("verification_methods")
                     .get<std::vector<Unlock::VerificationMethod>>();
  TC_RETURN(methods);
}

}
