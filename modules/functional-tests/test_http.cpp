
#include <Tanker/HttpClient.hpp>

#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <tconcurrent/coroutine.hpp>

#include <fmt/format.h>
#include <fmt/ostream.h>

#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Tanker/Crypto/EncryptionKeyPair.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/GhostDevice.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Users/EntryGenerator.hpp>

#include <mgs/base64url.hpp>

#include <Helpers/Config.hpp>
#include <doctest/doctest.h>

using Tanker::Functional::TrustchainFixture;

namespace
{
auto makeClient(Tanker::Trustchain::TrustchainId const& tid)
{
  using fetchpp::http::url;
  return Tanker::HttpClient(
      url(Tanker::TestConstants::appdUrl()),
      {"test", tid, "dev"},
      tc::get_default_executor().get_io_service().get_executor());
}

auto makeUser(Tanker::Functional::Trustchain& trustchain,
              Tanker::Functional::User const& user)
{
  using namespace fetchpp;
  auto ghostKeys = Tanker::DeviceKeys::create();
  auto ghostDevice = Tanker::GhostDevice::create(ghostKeys);
  auto const userKeysPair = Tanker::Crypto::makeEncryptionKeyPair();
  auto ghostCreation =
      Tanker::Users::createNewUserAction(trustchain.id,
                                         user.identity.delegation,
                                         ghostKeys.signatureKeyPair.publicKey,
                                         ghostKeys.encryptionKeyPair.publicKey,
                                         userKeysPair);
  auto deviceKeys = Tanker::DeviceKeys::create();
  auto deviceCreation = Tanker::Users::createNewDeviceAction(
      trustchain.id,
      Tanker::Trustchain::DeviceId{ghostCreation.hash()},
      Tanker::Identity::makeDelegation(user.userId,
                                       ghostKeys.signatureKeyPair.privateKey),
      deviceKeys.signatureKeyPair.publicKey,
      deviceKeys.encryptionKeyPair.publicKey,
      userKeysPair);
  auto verifKey = Tanker::Crypto::encryptAead(
      user.identity.userSecret,
      gsl::make_span(ghostDevice.toVerificationKey()).as_span<uint8_t const>());
  return std::make_tuple(ghostCreation, deviceCreation, verifKey, deviceKeys);
}

tc::cotask<
    std::tuple<std::string, Tanker::Trustchain::DeviceId, Tanker::DeviceKeys>>
createUser(Tanker::HttpClient& cl,
           Tanker::Functional::Trustchain& trustchain,
           Tanker::Functional::User const& user)
{
  auto [ghostCreation, deviceCreation, verifKey, deviceKeys] =
      makeUser(trustchain, user);
  auto const url = fmt::format("users/{userId:#S}",
                               fmt::arg("appId", trustchain.id),
                               fmt::arg("userId", user.userId));
  nlohmann::json res;
  res = TC_AWAIT(cl.asyncPost(
      url,
      {{"ghost_device_creation",
        mgs::base64::encode(Tanker::Serialization::serialize(ghostCreation))},
       {"first_device_creation",
        mgs::base64::encode(Tanker::Serialization::serialize(deviceCreation))},
       {"encrypted_verification_key", mgs::base64::encode(verifKey)}}));
  TC_RETURN(std::make_tuple(res.at("access_token").get<std::string>(),
                            deviceCreation.hash(),
                            deviceKeys));
}
}

TEST_SUITE_BEGIN("http_client");

TEST_CASE_FIXTURE(TrustchainFixture, "get a non-existent user")
{
  using namespace fetchpp;
  auto const user = trustchain.makeUser(Tanker::Functional::UserType::New);
  auto cl = makeClient(trustchain.id);
  auto const url = fmt::format("users/{userId:#S}",
                               fmt::arg("appId", trustchain.id),
                               fmt::arg("userId", user.userId));
  nlohmann::json res;
  REQUIRE_NOTHROW(res = TC_AWAIT(cl.asyncGet(url)));
  REQUIRE_EQ(res.at("error").at("status").get<int>(), 404);
  REQUIRE_EQ(res.at("error").at("code").get<std::string>(), "user_not_found");
}

TEST_CASE_FIXTURE(TrustchainFixture, "create a non-existent user")
{
  auto const user = trustchain.makeUser(Tanker::Functional::UserType::New);
  auto [ghostCreation, deviceCreation, verifKey, _] =
      makeUser(trustchain, user);
  auto const url =
      fmt::format("users/{userId:#S}", fmt::arg("userId", user.userId));
  auto cl = makeClient(trustchain.id);
  nlohmann::json res;
  REQUIRE_NOTHROW(
      res = TC_AWAIT(cl.asyncPost(
          url,
          {{"ghost_device_creation",
            mgs::base64::encode(
                Tanker::Serialization::serialize(ghostCreation))},
           {"first_device_creation",
            mgs::base64::encode(
                Tanker::Serialization::serialize(deviceCreation))},
           {"encrypted_verification_key", mgs::base64::encode(verifKey)}})));
  REQUIRE(res.contains("access_token"));
}

TEST_CASE_FIXTURE(TrustchainFixture, "open/close a http session")
{
  using namespace fetchpp;
  auto const user = trustchain.makeUser(Tanker::Functional::UserType::New);
  auto cl = makeClient(trustchain.id);
  auto [token, deviceId, deviceKeys] =
      TC_AWAIT(createUser(cl, trustchain, user));
  // cl.setAccessToken(http::authorization::bearer(token));

  nlohmann::json res;
  REQUIRE_NOTHROW(res = TC_AWAIT(cl.asyncPost(
                      fmt::format("devices/{deviceId:#S}/challenges",
                                  fmt::arg("deviceId", deviceId)))));
  std::string challenge;
  REQUIRE_NOTHROW(res.at("challenge").get_to(challenge));
  REQUIRE(challenge.size() > 20);
  auto sig =
      Tanker::Crypto::sign(gsl::make_span(challenge).as_span<uint8_t const>(),
                           deviceKeys.signatureKeyPair.privateKey);

  REQUIRE_NOTHROW(res = TC_AWAIT(cl.asyncPost(
                      fmt::format("devices/{deviceId:#S}/sessions",
                                  fmt::arg("deviceId", deviceId)),
                      {{"challenge", challenge}, {"signature", sig}})));
  std::string access_token;
  REQUIRE_NOTHROW(res.at("access_token").get_to(access_token));
  REQUIRE(access_token.size() == 43);
  cl.setAccessToken(http::authorization::bearer(access_token));
  TC_AWAIT(cl.asyncDelete(fmt::format("devices/{deviceId:#S}/sessions",
                                      fmt::arg("deviceId", deviceId))));
}

TEST_SUITE_END();