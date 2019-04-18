#include <doctest.h>

#include <Tanker/Client.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Crypto/Json/Json.hpp>
#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/Password.hpp>
#include <Tanker/Types/SUserId.hpp>
#include <Tanker/Types/UnlockKey.hpp>
#include <Tanker/Unlock/Messages.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>

#include "MockConnection.hpp"

#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

using namespace std::string_literals;

using namespace Tanker;
using namespace Tanker::type_literals;
using trompeloeil::_;
using trompeloeil::eq;

namespace
{
auto const someUnlockKey = UnlockKey{
    "eyJkZXZpY2VJZCI6IlFySHhqNk9qSURBUmJRVWdBenRmUHZyNFJVZUNRWDRhb1ZTWXJiSzNEa2"
    "s9IiwicHJpdmF0ZUVuY3J5cHRpb25LZXkiOiJQTnRjNEFXMWZ5NnBnbVd2SlA5RTN0ZytxMFJ0"
    "emkxdlcvSEFqQnBMRmdnPSIsInByaXZhdGVTaWduYXR1cmVLZXkiOiJxbXBNZmlHRHYweEZyVD"
    "dMVHZjTkFYQ2FrbFRWcE54Y1ByRjdycStKelhuZ2dleUo1YnR2YUlrWDlURmxMQjdKaU5ObmVo"
    "dXJjZEhRU05xMEgzQlJidz09In0="};
auto initClient()
{
  auto mockConnection = std::make_unique<MockConnection>();
  auto mconn = mockConnection.get();

  REQUIRE_CALL(*mconn, on("new relevant block", _));
  REQUIRE_CALL(*mconn, connect()).LR_SIDE_EFFECT(mconn->connected());
  REQUIRE_CALL(*mconn, wasConnected());

  auto c = std::make_unique<Client>(std::move(mockConnection));
  REQUIRE_NOTHROW(c->start());
  struct
  {
    std::unique_ptr<Client> c;
    MockConnection& mconn;
  } a{std::move(c), *mconn};
  return a;
}
}

TEST_CASE("Create the client")
{
  auto mockConnection = std::make_unique<MockConnection>();
  auto& mconn = *mockConnection.get();

  ALLOW_CALL(mconn, on("new relevant block", _));
  REQUIRE_NOTHROW(std::make_unique<Client>(std::move(mockConnection)));
}

TEST_CASE("start the client")
{
  initClient();
}

TEST_CASE("Client pushes")
{
  auto cl = initClient();

  SUBCASE("pushblock()")
  {
    auto const block = make_buffer("hello");
    REQUIRE_CALL(
        cl.mconn,
        emit("push block", eq(cppcodec::base64_rfc4648::encode(block))))
        .LR_RETURN(WRAP_COTASK(nlohmann::json{}.dump()));
    REQUIRE_NOTHROW(AWAIT_VOID(cl.c->pushBlock(block)));
  }
  SUBCASE("pushKeys()")
  {
    SUBCASE("push 0 keys")
    {
      REQUIRE_CALL(cl.mconn, emit("push keys", "[]"))
          .LR_RETURN(WRAP_COTASK(nlohmann::json{}.dump()));
      REQUIRE_NOTHROW(AWAIT_VOID(cl.c->pushKeys({})));
    }
    SUBCASE("push 3 keys")
    {
      auto const blocks = std::array<std::vector<uint8_t>, 3>{
          make_buffer("Hello"),
          make_buffer("This is my secret."),
          make_buffer("I have a lot of secrets."),
      };
      auto encoded_blocks = std::array<std::string, 3>{};
      std::transform(
          begin(blocks), end(blocks), begin(encoded_blocks), [](auto&& b) {
            return cppcodec::base64_rfc4648::encode(b);
          });
      REQUIRE_CALL(cl.mconn,
                   emit("push keys", nlohmann::json(encoded_blocks).dump()))
          .LR_RETURN(WRAP_COTASK(nlohmann::json{}.dump()));
      REQUIRE_NOTHROW(AWAIT_VOID(cl.c->pushKeys(blocks)));
    }
  }
}

TEST_CASE("Client authenticate")
{
  auto cl = initClient();

  auto const challenge_ref = "harder better stronger"s;
  auto const trustchainId =
      make<Trustchain::TrustchainId>("this is a trustchain id");

  SUBCASE("It requests a challenge")
  {
    REQUIRE_CALL(cl.mconn, emit("request auth challenge", "null"))
        .LR_RETURN(
            WRAP_COTASK(nlohmann::json{{"challenge", challenge_ref}}.dump()));
    auto const challenge = AWAIT(cl.c->requestAuthChallenge());
    REQUIRE(challenge == challenge_ref);
  }

  SUBCASE("It sends back the challenge and authenticate")
  {
    auto const signKeys = Crypto::makeSignatureKeyPair();
    auto const userId = obfuscateUserId("alice"_uid, trustchainId);

    auto signature =
        Crypto::sign(gsl::make_span(challenge_ref).as_span<uint8_t const>(),
                     signKeys.privateKey);
    auto const response = nlohmann::json{
        {"signature", signature},
        {"public_signature_key", signKeys.publicKey},
        {"trustchain_id", trustchainId},
        {"user_id", userId},
    };
    REQUIRE_CALL(cl.mconn, emit("authenticate device", response.dump()))
        .LR_RETURN(WRAP_COTASK(nlohmann::json(nullptr).dump()));
    REQUIRE_NOTHROW(AWAIT_VOID(cl.c->authenticateDevice(response)));
  }

  SUBCASE("It sends back a bad challenge and throws")
  {
    REQUIRE_CALL(cl.mconn, emit("authenticate device", _))
        .THROW(std::runtime_error("Device authentications fail"));
    REQUIRE_THROWS_AS(AWAIT_VOID(cl.c->authenticateDevice(
                          nlohmann::json{{"first", "second"}})),
                      std::runtime_error);
  }

  SUBCASE("It sends back the challenge and authenticate")
  {
    auto const signKeys = Crypto::makeSignatureKeyPair();
    auto const userId = obfuscateUserId("alice"_uid, trustchainId);

    auto signature =
        Crypto::sign(gsl::make_span(challenge_ref).as_span<uint8_t const>(),
                     signKeys.privateKey);
    auto const response = nlohmann::json{
        {"signature", signature},
        {"public_signature_key", signKeys.publicKey},
        {"trustchain_id", trustchainId},
        {"user_id", userId},
    };
    REQUIRE_CALL(cl.mconn, emit("authenticate device", response.dump()))
        .LR_RETURN(WRAP_COTASK(nlohmann::json(nullptr).dump()));
    REQUIRE_NOTHROW(AWAIT_VOID(cl.c->authenticateDevice(response)));
  }
}

TEST_CASE("Client getPublicProvisionalIdentities")
{
  auto cl = initClient();

  std::vector<Email> emails{Email{"alice@tanker.io"}, Email{"bob@tanker.io"}};

  nlohmann::json result;
  result[0]["SignaturePublicKey"] = Crypto::PublicSignatureKey{};
  result[0]["EncryptionPublicKey"] = Crypto::PublicEncryptionKey{};
  result[1]["SignaturePublicKey"] = Crypto::PublicSignatureKey{};
  result[1]["EncryptionPublicKey"] = Crypto::PublicEncryptionKey{};

  REQUIRE_CALL(
      cl.mconn,
      emit("get public provisional identities",
           R"([{"email":"alice@tanker.io"},{"email":"bob@tanker.io"}])"_json
               .dump()))
      .RETURN(WRAP_COTASK(result.dump()));
  auto res = AWAIT(cl.c->getPublicProvisionalIdentities(emails));
  FAST_REQUIRE_EQ(res.size(), 2);
}

TEST_CASE("Client getBlocks")
{
  auto cl = initClient();

  SUBCASE("It asks all the blocks since the 42th")
  {
    auto const userId = std::vector<GroupId>{make<GroupId>("team")};
    auto message = nlohmann::json{{"index", 42},
                                  {"extra_users", std::vector<std::string>{}},
                                  {"extra_groups", std::vector<std::string>{}}};
    REQUIRE_CALL(cl.mconn, emit("get blocks 2", message.dump()))
        .RETURN(
            WRAP_COTASK(nlohmann::json(std::vector<std::string>{5}).dump()));
    auto res = AWAIT(cl.c->getBlocks(42, {}, {}));
    FAST_REQUIRE_EQ(res.size(), 5);
  }
  SUBCASE("It asks all the blocks since the 42th, with some extra users")
  {
    auto extra_users = std::vector<Trustchain::UserId>{
        make<Trustchain::UserId>("alice"), make<Trustchain::UserId>("bob")};
    auto message = nlohmann::json{{"index", 42},
                                  {"extra_users", extra_users},
                                  {"extra_groups", std::vector<std::string>{}}};
    REQUIRE_CALL(cl.mconn, emit("get blocks 2", message.dump()))
        .RETURN(
            WRAP_COTASK(nlohmann::json(std::vector<std::string>{5}).dump()));
    auto res = AWAIT(cl.c->getBlocks(42, extra_users, {}));
    FAST_REQUIRE_EQ(res.size(), 5);
  }

  SUBCASE("It asks all the blocks since the 42th, with some extras")
  {
    auto extra_users = std::vector<Trustchain::UserId>{
        make<Trustchain::UserId>("alice"), make<Trustchain::UserId>("bob")};
    auto extra_groups =
        std::vector<GroupId>{make<GroupId>("party"), make<GroupId>("mode")};
    auto message = nlohmann::json{{"index", 42},
                                  {"extra_users", extra_users},
                                  {"extra_groups", extra_groups}};
    REQUIRE_CALL(cl.mconn, emit("get blocks 2", message.dump()))
        .RETURN(
            WRAP_COTASK(nlohmann::json(std::vector<std::string>{7}).dump()));
    auto res = AWAIT(cl.c->getBlocks(42, extra_users, extra_groups));
    FAST_REQUIRE_EQ(res.size(), 7);
  }
}

TEST_CASE("Client subscribe to creation")
{
  auto cl = initClient();
  auto trustchainId = make<Trustchain::TrustchainId>("My Trustchain");
  auto sigKp = Crypto::SignatureKeyPair{
      make<Crypto::PublicSignatureKey>("a very public key"),
      make<Crypto::PrivateSignatureKey>("a very private key")};
  auto sig = Crypto::sign(sigKp.publicKey, sigKp.privateKey);
  auto req = nlohmann::json({
      {"trustchain_id", trustchainId},
      {"public_signature_key", sigKp.publicKey},
      {"signature", sig},
  });
  REQUIRE_CALL(cl.mconn, emit("subscribe to creation", req.dump()))
      .RETURN(WRAP_COTASK(nlohmann::json(nullptr).dump()));
  SUBCASE("it does not throw")
  {
    REQUIRE_CALL(cl.mconn, on("device created", _));
    REQUIRE_NOTHROW(AWAIT_VOID(
        cl.c->subscribeToCreation(trustchainId, sigKp.publicKey, sig)));
  }
}

TEST_CASE("Client unlock api")
{
  auto const trustchainId = make<Trustchain::TrustchainId>("my trustchainId");
  auto const userId = make<Trustchain::UserId>("alice");
  auto const password = Password{"some secret"};
  auto const email = Email{"alice@aol.com"};

  auto deviceKeys = DeviceKeys::create();
  auto const aliceUserSecret =
      make<Crypto::SymmetricKey>("this is alice's userSecret");
  auto const message =
      Unlock::Message(trustchainId,
                      deviceKeys.deviceId,
                      Unlock::UpdateOptions(email, password, someUnlockKey),
                      aliceUserSecret,
                      deviceKeys.signatureKeyPair.privateKey);

  SUBCASE("createUnlockKey()")
  {
    auto cl = initClient();
    REQUIRE_CALL(cl.mconn,
                 emit("create unlock key", eq(nlohmann::json(message).dump())))
        .LR_RETURN(WRAP_COTASK(nlohmann::json{}.dump()));
    REQUIRE_NOTHROW(AWAIT_VOID(cl.c->createUnlockKey(message)));
  }

  SUBCASE("uploadUnlockKey()")
  {
    auto cl = initClient();
    REQUIRE_CALL(cl.mconn,
                 emit("update unlock key", eq(nlohmann::json(message).dump())))
        .LR_RETURN(WRAP_COTASK(nlohmann::json{}.dump()));
    REQUIRE_NOTHROW(AWAIT_VOID(cl.c->updateUnlockKey(message)));
  }

  SUBCASE("fetchUnlockKey()")
  {
    auto cl = initClient();
    auto const request = Unlock::Request(trustchainId, userId, password);

    REQUIRE_CALL(cl.mconn,
                 emit("get unlock key", eq(nlohmann::json(request).dump())))
        .LR_RETURN(WRAP_COTASK(
            nlohmann::json(Unlock::FetchAnswer(aliceUserSecret, someUnlockKey))
                .dump()));
    auto const fetchAnswer = AWAIT(cl.c->fetchUnlockKey(request));
    auto const unlockKey = fetchAnswer.getUnlockKey(aliceUserSecret);
    FAST_REQUIRE_EQ(someUnlockKey, unlockKey);
  }
}
