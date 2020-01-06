
#include <Tanker/Users/Requester.hpp>

#include <Tanker/Client.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Errors/ServerErrcCategory.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Tracer/ScopeTimer.hpp>
#include <Tanker/Users/LocalUser.hpp>

#include <boost/algorithm/string/predicate.hpp>
#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

namespace Tanker::Users
{
Requester::Requester(Client* client) : _client(client)
{
}

tc::cotask<UserStatusResult> Requester::userStatus(
    Trustchain::TrustchainId const& trustchainId,
    Trustchain::UserId const& userId,
    Crypto::PublicSignatureKey const& publicSignatureKey)
{
  FUNC_TIMER(Proc);
  nlohmann::json request{
      {"trustchain_id", trustchainId},
      {"user_id", userId},
      {"device_public_signature_key", publicSignatureKey},
  };

  auto const reply = TC_AWAIT(_client->emit("get user status", request));

  TC_RETURN(reply.get<UserStatusResult>());
}

tc::cotask<std::vector<Trustchain::ServerEntry>> Requester::getMe()
{
  auto const response = TC_AWAIT(_client->emit("get my user blocks", {}));
  auto const ret = Trustchain::fromBlocksToServerEntries(
      response.get<std::vector<std::string>>());
  TC_RETURN(ret);
}

tc::cotask<std::vector<Trustchain::ServerEntry>> Requester::getUsers(
    gsl::span<Trustchain::UserId const> userIds)
{
  auto const response =
      TC_AWAIT(_client->emit("get users blocks", {{"user_ids", userIds}}));
  auto const ret = Trustchain::fromBlocksToServerEntries(
      response.get<std::vector<std::string>>());
  TC_RETURN(ret);
}

tc::cotask<void> Requester::authenticate(
    Trustchain::TrustchainId const& trustchainId, LocalUser const& localUser)
{
  FUNC_TIMER(Net);
  auto const challenge = TC_AWAIT(_client->emit("request auth challenge", {}))
                             .at("challenge")
                             .get<std::string>();
  // NOTE: It is MANDATORY to check this prefix is valid, or the server could
  // get us to sign anything!
  if (!boost::algorithm::starts_with(
          challenge, u8"\U0001F512 Auth Challenge. 1234567890."))
  {
    throw formatEx(
        Errors::Errc::InternalError,
        "received auth challenge does not contain mandatory prefix, server "
        "may not be up to date, or we may be under attack.");
  }
  auto const signature =
      Crypto::sign(gsl::make_span(challenge).as_span<uint8_t const>(),
                   localUser.deviceKeys().signatureKeyPair.privateKey);
  auto const request =
      nlohmann::json{{"signature", signature},
                     {"public_signature_key",
                      localUser.deviceKeys().signatureKeyPair.publicKey},
                     {"trustchain_id", trustchainId},
                     {"user_id", localUser.userId()}};
  try
  {
    TC_AWAIT(_client->emit("authenticate device", request));
  }
  catch (Errors::Exception const& ex)
  {
    if (ex.errorCode().category() == Errors::ServerErrcCategory())
      throw Errors::formatEx(Errors::Errc::InternalError,
                             "device authentication failed");
  }
}

void from_json(nlohmann::json const& j, UserStatusResult& result)
{
  j.at("device_exists").get_to(result.deviceExists);
  result.userExists = j.at("user_exists").get<bool>();
  auto const lastReset = j.at("last_reset").get<std::string>();
  if (!lastReset.empty())
    result.lastReset =
        cppcodec::base64_rfc4648::decode<Crypto::Hash>(lastReset);
  else
    result.lastReset = Crypto::Hash{};
}
}
