#include <Tanker/EncryptionSession.hpp>
#include <Tanker/Encryptor.hpp>

#include <Helpers/Await.hpp>
#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <doctest.h>

using namespace Tanker;
using namespace Tanker::Errors;

TEST_SUITE("Ecryption session tests")
{
  TEST_CASE("decryptedSize and encryptedSize should be symmetrical")
  {
    std::vector<uint8_t> a0(EncryptionSession::encryptedSize(0));
    Serialization::varint_write(a0.data(), EncryptionSession::version());
    std::vector<uint8_t> a42(EncryptionSession::encryptedSize(42));
    Serialization::varint_write(a42.data(), EncryptionSession::version());
    CHECK(EncryptionSession::decryptedSize(a0) == 0);
    CHECK(EncryptionSession::decryptedSize(a42) == 42);
  }

  TEST_CASE("encrypt/decrypt should work with an empty buffer")
  {
    std::vector<uint8_t> clearData;
    std::vector<uint8_t> encryptedData(
        EncryptionSession::encryptedSize(clearData.size()));
    auto session = EncryptionSession();

    auto const metadata =
        AWAIT(session.encrypt(encryptedData.data(), clearData));

    std::vector<uint8_t> decryptedData(
        EncryptionSession::decryptedSize(encryptedData));

    AWAIT_VOID(
        Encryptor::decrypt(decryptedData.data(), metadata.key, encryptedData));

    CHECK(clearData == decryptedData);
  }

  TEST_CASE("encrypt/decrypt should work with a normal buffer")
  {
    auto clearData = make_buffer("this is the data to encrypt");
    std::vector<uint8_t> encryptedData(
        EncryptionSession::encryptedSize(clearData.size()));
    auto session = EncryptionSession();

    auto const metadata =
        AWAIT(session.encrypt(encryptedData.data(), clearData));

    std::vector<uint8_t> decryptedData(
        EncryptionSession::decryptedSize(encryptedData));
    AWAIT_VOID(
        Encryptor::decrypt(decryptedData.data(), metadata.key, encryptedData));

    CHECK(clearData == decryptedData);
  }

  TEST_CASE("encrypt should never give the same result twice")
  {
    auto clearData = make_buffer("this is the data to encrypt");
    auto session = EncryptionSession();

    std::vector<uint8_t> encryptedData1(
        EncryptionSession::encryptedSize(clearData.size()));
    AWAIT(session.encrypt(encryptedData1.data(), clearData));
    std::vector<uint8_t> encryptedData2(
        EncryptionSession::encryptedSize(clearData.size()));
    AWAIT(session.encrypt(encryptedData2.data(), clearData));

    CHECK(encryptedData1 != encryptedData2);
  }

  TEST_CASE("decrypt should not work with a corrupted buffer")
  {
    auto const clearData = make_buffer("this is very secret");
    auto session = EncryptionSession();

    std::vector<uint8_t> encryptedData(
        EncryptionSession::encryptedSize(clearData.size()));
    auto const metadata =
        AWAIT(session.encrypt(encryptedData.data(), clearData));

    std::vector<uint8_t> decryptedData(
        EncryptionSession::decryptedSize(encryptedData));

    encryptedData[2]++;

    TANKER_CHECK_THROWS_WITH_CODE(
        AWAIT_VOID(Encryptor::decrypt(
            decryptedData.data(), metadata.key, encryptedData)),
        Errc::DecryptionFailed);
  }

  TEST_CASE("Session's resourceId should match metadata and V5 resource ID")
  {
    auto clearData = make_buffer("this is the data to encrypt");
    auto session = EncryptionSession();
    std::vector<uint8_t> encryptedData(
        EncryptionSession::encryptedSize(clearData.size()));

    auto const metadata =
        AWAIT(session.encrypt(encryptedData.data(), clearData));

    CHECK(session.resourceId() == metadata.resourceId);
    CHECK(EncryptorV5::extractResourceId(encryptedData) == metadata.resourceId);
  }

  TEST_CASE("resourceId is the same for all session encryptions")
  {
    auto clearData1 = make_buffer("Rotating locomotion in living systems");
    auto clearData2 = make_buffer("Gondwanatheria, an enigmatic extinct group");
    auto session = EncryptionSession();

    std::vector<uint8_t> encryptedData1(
        EncryptionSession::encryptedSize(clearData1.size()));
    auto const meta1 =
        AWAIT(session.encrypt(encryptedData1.data(), clearData1));
    std::vector<uint8_t> encryptedData2(
        EncryptionSession::encryptedSize(clearData2.size()));
    auto const meta2 =
        AWAIT(session.encrypt(encryptedData2.data(), clearData2));

    CHECK(meta1.resourceId == meta2.resourceId);
  }

  TEST_CASE("encryption key is the same for all session encryptions")
  {
    auto clearData1 =
        make_buffer("The Australian Cattle Dog is energetic and intelligent");
    auto clearData2 = make_buffer("It nests in hollows of gum trees");
    auto session = EncryptionSession();

    std::vector<uint8_t> encryptedData1(
        EncryptionSession::encryptedSize(clearData1.size()));
    auto const meta1 =
        AWAIT(session.encrypt(encryptedData1.data(), clearData1));
    std::vector<uint8_t> encryptedData2(
        EncryptionSession::encryptedSize(clearData2.size()));
    auto const meta2 =
        AWAIT(session.encrypt(encryptedData2.data(), clearData2));

    CHECK(meta1.resourceId == meta2.resourceId);
  }
}
