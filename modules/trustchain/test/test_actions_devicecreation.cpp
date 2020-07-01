#include <Tanker/Trustchain/Actions/DeviceCreation.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v1.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v2.hpp>
#include <Tanker/Trustchain/Actions/DeviceCreation/v3.hpp>
#include <Tanker/Trustchain/Errors/Errc.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Serialization/Serialization.hpp>
#include <Tanker/Trustchain/UserId.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <doctest/doctest.h>

using namespace Tanker;
using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

TEST_CASE("DeviceCreation tests")
{
  SUBCASE("DeviceCreation variant functions")
  {
    DeviceCreation dc;

    CHECK(dc.holds_alternative<DeviceCreation::v1>());
    CHECK(dc.get_if<DeviceCreation::v1>() != nullptr);
    CHECK(dc.get_if<DeviceCreation::v3>() == nullptr);
    CHECK_NOTHROW(dc.get<DeviceCreation::v1>());
    CHECK_THROWS_AS(dc.get<DeviceCreation::v3>(),
                    boost::variant2::bad_variant_access);
    CHECK(dc.visit([](auto const& val) { return val.nature(); }) ==
          Nature::DeviceCreation1);
  }

  SUBCASE("DeviceCreation v2 conversion to v1")
  {
    Crypto::PublicSignatureKey ephemeralPublicSignatureKey{};
    UserId userId{};
    Crypto::Signature delegationSignature{};
    Crypto::PublicSignatureKey publicSignatureKey{};
    Crypto::PublicEncryptionKey publicEncryptionKey{};
    Crypto::Hash lastReset{};

    REQUIRE(lastReset.is_null());

    SUBCASE("can convert with a zero-filled lastReset field")
    {
      DeviceCreation2 dc2({},
                          lastReset,
                          ephemeralPublicSignatureKey,
                          userId,
                          delegationSignature,
                          publicSignatureKey,
                          publicEncryptionKey,
                          {},
                          {},
                          {});

      CHECK_NOTHROW(dc2.asDeviceCreation1());
    }

    SUBCASE("throws if lastReset is not zero-filled")
    {
      lastReset[0]++;
      DeviceCreation2 dc2({},
                          lastReset,
                          ephemeralPublicSignatureKey,
                          userId,
                          delegationSignature,
                          publicSignatureKey,
                          publicEncryptionKey,
                          {},
                          {},
                          {});

      TANKER_CHECK_THROWS_WITH_CODE(dc2.asDeviceCreation1(),
                                    Errc::InvalidLastResetField);
    }
  }
}

TEST_CASE("Serialization test vectors")
{
  SUBCASE("it should serialize/deserialize a DeviceCreation v1")
  {
    // clang-format off
    std::vector<std::uint8_t> const serializedDevice = {
      // varint version
      0x01,
      // varint index
      0x00,
      // trustchain id
      0x74, 0x72, 0x75, 0x73, 0x74, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x20, 0x69,
      0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // varint nature
      0x02,
      // varint payload size
      0xc0, 0x01,
      // ephemeral public key
      0x65, 0x70, 0x68, 0x20, 0x70, 0x75, 0x62, 0x20, 0x6b, 0x65, 0x79, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // user id
      0x75, 0x73, 0x65, 0x72, 0x20, 0x69, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // delegation signature
      0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x73,
      0x69, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      // public signature key
      0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x61,
      0x74, 0x75, 0x72, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // public encryption key
      0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x65, 0x6e, 0x63, 0x20, 0x6b,
      0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // author
      0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // signature
      0x73, 0x69, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
    };
    // clang-format on

    auto const trustchainId = make<TrustchainId>("trustchain id");
    auto const author = make<Crypto::Hash>("author");
    auto const signature = make<Crypto::Signature>("sig");

    auto const ephemeralPublicSignatureKey =
        make<Crypto::PublicSignatureKey>("eph pub key");
    auto const userId = make<Trustchain::UserId>("user id");
    auto const delegationSignature = make<Crypto::Signature>("delegation sig");
    auto const publicSignatureKey =
        make<Crypto::PublicSignatureKey>("public signature key");
    auto const publicEncryptionKey =
        make<Crypto::PublicEncryptionKey>("public enc key");
    auto const hash = mgs::base64::decode<Crypto::Hash>(
        "nPmcskd1KiuDywCkM0ltRXk2e5eTpy+GxlKKhdRWq8s=");

    DeviceCreation::v1 const dc1(trustchainId,
                                 ephemeralPublicSignatureKey,
                                 userId,
                                 delegationSignature,
                                 publicSignatureKey,
                                 publicEncryptionKey,
                                 author,
                                 hash,
                                 signature);

    CHECK(Serialization::serialize(dc1) == serializedDevice);
    CHECK(Serialization::deserialize<DeviceCreation::v1>(serializedDevice) ==
          dc1);
  }

  SUBCASE("it should serialize/deserialize a DeviceCreation v2")
  {
    // clang-format off
    std::vector<std::uint8_t> const serializedDevice = {
      // varint version
      0x01,
      // varint index
      0x00,
      // trustchain id
      0x74, 0x72, 0x75, 0x73, 0x74, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x20, 0x69,
      0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // varint nature
      0x06,
      // varint payload size
      0xe0, 0x01,
      // last reset
      0x72, 0x65, 0x73, 0x65, 0x74, 0x20, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // ephemeral public signature key
      0x65, 0x70, 0x68, 0x20, 0x70, 0x75, 0x62, 0x20, 0x6b, 0x65, 0x79, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // user id
      0x75, 0x73, 0x65, 0x72, 0x20, 0x69, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // delegation signature
      0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x73,
      0x69, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      // public signature key
      0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x61,
      0x74, 0x75, 0x72, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // public encryption key
      0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x65, 0x6e, 0x63, 0x20, 0x6b,
      0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // author
      0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // signature
      0x73, 0x69, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
    };
    // clang-format on

    auto const trustchainId = make<TrustchainId>("trustchain id");
    auto const author = make<Crypto::Hash>("author");
    auto const signature = make<Crypto::Signature>("sig");

    auto const ephemeralPublicSignatureKey =
        make<Crypto::PublicSignatureKey>("eph pub key");
    auto const userId = make<Trustchain::UserId>("user id");
    auto const delegationSignature = make<Crypto::Signature>("delegation sig");
    auto const publicSignatureKey =
        make<Crypto::PublicSignatureKey>("public signature key");
    auto const publicEncryptionKey =
        make<Crypto::PublicEncryptionKey>("public enc key");
    auto const lastReset = make<Crypto::Hash>("reset block");
    auto const hash = mgs::base64::decode<Crypto::Hash>(
        "Hy0ykBdASXL5eigQ22Bb6rYEqe6vMfHkqU8o+BdyF4k=");

    DeviceCreation2 const dc2(trustchainId,
                              lastReset,
                              ephemeralPublicSignatureKey,
                              userId,
                              delegationSignature,
                              publicSignatureKey,
                              publicEncryptionKey,
                              author,
                              hash,
                              signature);

    CHECK(Serialization::serialize(dc2) == serializedDevice);
    CHECK(Serialization::deserialize<DeviceCreation2>(serializedDevice) == dc2);
  }

  SUBCASE("it should serialize/deserialize a DeviceCreation v3")
  {
    // clang-format off
    std::vector<std::uint8_t> const serializedDevice = {
      // varint version
      0x01,
      // varint index
      0x00,
      // trustchain id
      0x74, 0x72, 0x75, 0x73, 0x74, 0x63, 0x68, 0x61, 0x69, 0x6e, 0x20, 0x69,
      0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // varint nature
      0x07,
      // varint payload size
      0xb1, 0x02,
      // eph pub key
      0x65, 0x70, 0x68, 0x20, 0x70, 0x75, 0x62, 0x20, 0x6b, 0x65, 0x79, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // user id
      0x75, 0x73, 0x65, 0x72, 0x20, 0x69, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // delegation sig
      0x64, 0x65, 0x6c, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x20, 0x73,
      0x69, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      // public signature key
      0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x73, 0x69, 0x67, 0x6e, 0x61,
      0x74, 0x75, 0x72, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // public enc key
      0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x20, 0x65, 0x6e, 0x63, 0x20, 0x6b,
      0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // user pub enc key
      0x75, 0x73, 0x65, 0x72, 0x20, 0x70, 0x75, 0x62, 0x20, 0x65, 0x6e, 0x63,
      0x20, 0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // key
      0x6b, 0x65, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // IsGhostDevice
      0x01,
      // author
      0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // signature
      0x73, 0x69, 0x67, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
    };
    // clang-format on

    auto const trustchainId = make<TrustchainId>("trustchain id");
    auto const author = make<Crypto::Hash>("author");
    auto const signature = make<Crypto::Signature>("sig");

    auto const ephemeralPublicSignatureKey =
        make<Crypto::PublicSignatureKey>("eph pub key");
    auto const userId = make<Trustchain::UserId>("user id");
    auto const delegationSignature = make<Crypto::Signature>("delegation sig");
    auto const publicSignatureKey =
        make<Crypto::PublicSignatureKey>("public signature key");
    auto const publicEncryptionKey =
        make<Crypto::PublicEncryptionKey>("public enc key");
    auto const publicUserEncryptionKey =
        make<Crypto::PublicEncryptionKey>("user pub enc key");
    auto const sealedPrivateUserEncryptionKey =
        make<Crypto::SealedPrivateEncryptionKey>("key");
    auto const hash = mgs::base64::decode<Crypto::Hash>(
        "AEYXc2xMBM/E0xk3zLLMxSMkUPh4/iSuEurrQ3mrQiw=");

    DeviceCreation::v3 const dc3(trustchainId,
                                 ephemeralPublicSignatureKey,
                                 userId,
                                 delegationSignature,
                                 publicSignatureKey,
                                 publicEncryptionKey,
                                 publicUserEncryptionKey,
                                 sealedPrivateUserEncryptionKey,
                                 true,
                                 author,
                                 hash,
                                 signature);

    CHECK(Serialization::serialize(dc3) == serializedDevice);
    CHECK(Serialization::deserialize<DeviceCreation::v3>(serializedDevice) ==
          dc3);
  }
}
