#include <Tanker/EncryptionSession.hpp>

#include <Tanker/Encryptor.hpp>
#include <Tanker/Encryptor/Padding.hpp>
#include <Tanker/Encryptor/v5.hpp>
#include <Tanker/Encryptor/v7.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <doctest/doctest.h>
#include <memory>
#include <optional>

using namespace Tanker;
using namespace Tanker::Errors;

namespace
{
auto makeSession()
{
  // libc++.9 does not implement that
  // return std::reinterpret_pointer_cast<Session>(std::make_shared<int>());
  auto tmp = std::make_shared<int>();
  using Ptr = std::shared_ptr<Session>;
  return Ptr(tmp, reinterpret_cast<typename Ptr::element_type*>(tmp.get()));
}

class FixtureSession
{
public:
  FixtureSession() : session(makeSession())
  {
  }

protected:
  std::shared_ptr<Session> session;
};

void commonEncSessionTests(std::shared_ptr<Session>& session,
                           EncryptionSession encSession)
{
  SUBCASE("encrypt should never give the same result twice")
  {
    auto clearData = make_buffer("this is the data to encrypt");

    std::vector<uint8_t> encryptedData1(
        encSession.encryptedSize(clearData.size()));
    AWAIT(encSession.encrypt(encryptedData1.data(), clearData));
    std::vector<uint8_t> encryptedData2(
        encSession.encryptedSize(clearData.size()));
    AWAIT(encSession.encrypt(encryptedData2.data(), clearData));

    CHECK(encryptedData1 != encryptedData2);
  }

  SUBCASE("decrypt should not work with a corrupted buffer")
  {
    auto const clearData = make_buffer("this is very secret");

    std::vector<uint8_t> encryptedData(
        encSession.encryptedSize(clearData.size()));
    auto const metadata =
        AWAIT(encSession.encrypt(encryptedData.data(), clearData));

    std::vector<uint8_t> decryptedData(
        EncryptionSession::decryptedSize(encryptedData));

    encryptedData[2]++;

    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT(Encryptor::decrypt(
            decryptedData.data(), metadata.key, encryptedData)),
        Errc::DecryptionFailed);
  }

  SUBCASE("Session's resourceId should match metadata and V7 resource ID")
  {
    auto clearData = make_buffer("this is the data to encrypt");
    std::vector<uint8_t> encryptedData(
        encSession.encryptedSize(clearData.size()));

    auto const metadata =
        AWAIT(encSession.encrypt(encryptedData.data(), clearData));

    CHECK(encSession.resourceId() == metadata.resourceId);
    CHECK(EncryptorV7::extractResourceId(encryptedData) == metadata.resourceId);
  }

  SUBCASE("resourceId is the same for all session encryptions")
  {
    auto clearData1 = make_buffer("Rotating locomotion in living systems");
    auto clearData2 = make_buffer("Gondwanatheria, an enigmatic extinct group");

    std::vector<uint8_t> encryptedData1(
        encSession.encryptedSize(clearData1.size()));
    auto const meta1 =
        AWAIT(encSession.encrypt(encryptedData1.data(), clearData1));
    std::vector<uint8_t> encryptedData2(
        encSession.encryptedSize(clearData2.size()));
    auto const meta2 =
        AWAIT(encSession.encrypt(encryptedData2.data(), clearData2));

    CHECK(meta1.resourceId == meta2.resourceId);
  }

  SUBCASE("encryption key is the same for all session encryptions")
  {
    auto clearData1 =
        make_buffer("The Australian Cattle Dog is energetic and intelligent");
    auto clearData2 = make_buffer("It nests in hollows of gum trees");

    std::vector<uint8_t> encryptedData1(
        encSession.encryptedSize(clearData1.size()));
    auto const meta1 =
        AWAIT(encSession.encrypt(encryptedData1.data(), clearData1));
    std::vector<uint8_t> encryptedData2(
        encSession.encryptedSize(clearData2.size()));
    auto const meta2 =
        AWAIT(encSession.encrypt(encryptedData2.data(), clearData2));

    CHECK(meta1.resourceId == meta2.resourceId);
  }

  SUBCASE("cannot encrypt if a session has been reset")
  {
    auto clearData = make_buffer("It nests in hollows of gum trees");
    std::vector<uint8_t> encryptedData(
        encSession.encryptedSize(clearData.size()));

    session.reset();
    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT(encSession.encrypt(encryptedData.data(), clearData)),
        Errc::PreconditionFailed);

    TANKER_CHECK_THROWS_WITH_CODE(encSession.resourceId(),
                                  Errc::PreconditionFailed);

    TANKER_CHECK_THROWS_WITH_CODE(encSession.sessionKey(),
                                  Errc::PreconditionFailed);
  }
}
}

TEST_SUITE_BEGIN("Ecryption session tests");

TEST_CASE_FIXTURE(FixtureSession, "encryption session tests with auto padding")
{
  commonEncSessionTests(session, EncryptionSession(session, std::nullopt));
}

TEST_CASE_FIXTURE(FixtureSession, "encryption session tests with no padding")
{
  auto encSession = EncryptionSession(session, Padding::Off);
  commonEncSessionTests(session, encSession);

  SUBCASE("decryptedSize and encryptedSize should be symmetrical")
  {
    std::vector<uint8_t> a0(encSession.encryptedSize(0));
    Serialization::varint_write(a0.data(), EncryptorV5::version());
    std::vector<uint8_t> a42(encSession.encryptedSize(42));
    Serialization::varint_write(a42.data(), EncryptorV5::version());
    CHECK(EncryptionSession::decryptedSize(a0) == 0);
    CHECK(EncryptionSession::decryptedSize(a42) == 42);
  }
}

TEST_CASE_FIXTURE(FixtureSession,
                  "encryption session tests with a padding step")
{
  auto const step = 13;
  auto encSession = EncryptionSession(session, step);
  commonEncSessionTests(session, encSession);

  SUBCASE("encrypt multiple messages with the same padding step")
  {
    auto const encryptionOverhead = 57;
    auto const clearDatas = {
        "",
        "short",
        "the length of this message is definitely bigger than the step",
    };

    for (auto const str : clearDatas)
    {
      auto const clearData = make_buffer(str);
      std::vector<uint8_t> encryptedData(
          encSession.encryptedSize(clearData.size()));
      AWAIT(encSession.encrypt(encryptedData.data(), clearData));

      auto const unpaddedSize = encryptedData.size() - encryptionOverhead;
      CHECK_GT(unpaddedSize, clearData.size());
      CHECK_EQ(unpaddedSize % step, 0);
    }
  }
}

TEST_SUITE_END();
