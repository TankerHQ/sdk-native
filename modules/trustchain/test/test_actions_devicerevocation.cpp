#include <Tanker/Trustchain/Actions/DeviceRevocation.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation/v1.hpp>
#include <Tanker/Trustchain/Actions/DeviceRevocation/v2.hpp>

#include <Tanker/Serialization/Serialization.hpp>

#include <Helpers/Buffers.hpp>

#include <doctest.h>

using namespace Tanker;
using namespace Tanker::Trustchain;
using namespace Tanker::Trustchain::Actions;

TEST_CASE("DeviceRevocation tests")
{
  SUBCASE("DeviceRevocation variant functions")
  {
    DeviceRevocation dc;

    CHECK(dc.holds_alternative<DeviceRevocation::v1>());
    CHECK(dc.get_if<DeviceRevocation::v1>() != nullptr);
    CHECK(dc.get_if<DeviceRevocation::v2>() == nullptr);
    CHECK_NOTHROW(dc.get<DeviceRevocation::v1>());
    CHECK_THROWS_AS(dc.get<DeviceRevocation::v2>(),
                    boost::variant2::bad_variant_access);
    CHECK(dc.visit([](auto const& val) { return val.nature(); }) ==
          Nature::DeviceRevocation);
  }
}

TEST_CASE("Serialization test vectors")
{
  SUBCASE("it should serialize/deserialize a DeviceRevocation v1")
  {
    // clang-format off
    std::vector<std::uint8_t> const serializedDeviceRevocation = {
      // device id
      0xe9, 0x0b, 0x0a, 0x13, 0x05, 0xb1, 0x82, 0x85, 0xab, 0x9d, 0xbe, 0x3f,
      0xdb, 0x57, 0x2b, 0x71, 0x6c, 0x0d, 0xa1, 0xa3, 0xad, 0xb8, 0x86, 0x9b,
      0x39, 0x58, 0xcb, 0x00, 0xfa, 0x31, 0x5d, 0x87
    };
    // clang-format on

    DeviceRevocation::v1 const dr1{DeviceId(serializedDeviceRevocation)};
    CHECK(Serialization::deserialize<DeviceRevocation::v1>(
              serializedDeviceRevocation) == dr1);
    CHECK(Serialization::serialize(dr1) == serializedDeviceRevocation);
  }

  SUBCASE("it should serialize/deserialize a DeviceRevocation v2")
  {
    std::vector<std::uint8_t> const serializedDeviceId{
        0xe9, 0x0b, 0x0a, 0x13, 0x05, 0xb1, 0x82, 0x85, 0xab, 0x9d, 0xbe,
        0x3f, 0xdb, 0x57, 0x2b, 0x71, 0x6c, 0x0d, 0xa1, 0xa3, 0xad, 0xb8,
        0x86, 0x9b, 0x39, 0x58, 0xcb, 0x00, 0xfa, 0x31, 0x5d, 0x87};

    std::vector<std::uint8_t> const serializedPublicEncryptionKey{
        0x42, 0x9a, 0xfa, 0x09, 0xee, 0xea, 0xce, 0x12, 0xec, 0x59, 0x06,
        0x35, 0xa8, 0x7f, 0x82, 0xe6, 0x39, 0xc8, 0xce, 0xd0, 0xc8, 0xe5,
        0x57, 0x16, 0x72, 0x94, 0x9e, 0xfb, 0xed, 0x59, 0xde, 0x2e};

    std::vector<std::uint8_t> const serializedPreviousPublicEncryptionKey{
        0x8e, 0x3e, 0x33, 0x57, 0x3d, 0xd5, 0x3c, 0xe7, 0x29, 0xbc, 0x73,
        0x90, 0x7f, 0x83, 0x20, 0xee, 0xe9, 0x0b, 0x0a, 0x13, 0x05, 0xb1,
        0x82, 0x85, 0xab, 0x9d, 0xbe, 0x3f, 0xdb, 0x57, 0x2b, 0x71};

    std::vector<std::uint8_t> const serializedSealedKeyForPreviousUser{
        0xf1, 0x28, 0xa8, 0x12, 0x03, 0x8e, 0x7c, 0x9c, 0x39, 0xad, 0x73, 0x21,
        0xa3, 0xee, 0x50, 0x53, 0xc1, 0x1d, 0xda, 0x76, 0xaf, 0xc8, 0xfd, 0x70,
        0x74, 0x5c, 0xbb, 0xd6, 0xb8, 0x7f, 0x8f, 0x6b, 0xe1, 0xaf, 0x36, 0x80,
        0x3f, 0xf3, 0xbc, 0xb2, 0xfb, 0x4e, 0xe1, 0x7d, 0xea, 0xbd, 0x19, 0x6b,
        0x8e, 0x3e, 0x33, 0x57, 0x3d, 0xd5, 0x3c, 0xe7, 0x29, 0xbc, 0x73, 0x90,
        0x7f, 0x83, 0x20, 0xee, 0x0e, 0xc0, 0x91, 0x63, 0xe7, 0xc2, 0x04, 0x69,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    std::vector<std::uint8_t> const serializedRecipientDeviceId{
        0xd0, 0xa8, 0x9e, 0xff, 0x7d, 0x59, 0x48, 0x3a, 0xee, 0x7c, 0xe4,
        0x99, 0x49, 0x4d, 0x1c, 0xd7, 0x87, 0x54, 0x41, 0xf5, 0xba, 0x51,
        0xd7, 0x65, 0xbf, 0x91, 0x45, 0x08, 0x03, 0xf1, 0xe9, 0xc7};

    std::vector<std::uint8_t> const serializedSealedUserKeyForRecipient{
        0xe1, 0xaf, 0x36, 0x80, 0x3f, 0xf3, 0xbc, 0xb2, 0xfb, 0x4e, 0xe1, 0x7d,
        0xea, 0xbd, 0x19, 0x6b, 0x8e, 0x3e, 0x33, 0x57, 0x3d, 0xd5, 0x3c, 0xe7,
        0x29, 0xbc, 0x73, 0x90, 0x7f, 0x83, 0x20, 0xee, 0xf1, 0x28, 0xa8, 0x12,
        0x03, 0x8e, 0x7c, 0x9c, 0x39, 0xad, 0x73, 0x21, 0xa3, 0xee, 0x50, 0x53,
        0xc1, 0x1d, 0xda, 0x76, 0xaf, 0xc8, 0xfd, 0x70, 0x74, 0x5c, 0xbb, 0xd6,
        0xb8, 0x7f, 0x8f, 0x6b, 0x0e, 0xc0, 0x91, 0x63, 0xe7, 0xc2, 0x04, 0x69,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // clang-format off
    std::vector<std::uint8_t> const serializedDeviceRevocation = {
      // device id
      0xe9, 0x0b, 0x0a, 0x13, 0x05, 0xb1, 0x82, 0x85, 0xab, 0x9d, 0xbe, 0x3f,
      0xdb, 0x57, 0x2b, 0x71, 0x6c, 0x0d, 0xa1, 0xa3, 0xad, 0xb8, 0x86, 0x9b,
      0x39, 0x58, 0xcb, 0x00, 0xfa, 0x31, 0x5d, 0x87,
      // public encryption key
      0x42, 0x9a, 0xfa, 0x09, 0xee, 0xea, 0xce, 0x12, 0xec, 0x59, 0x06, 0x35,
      0xa8, 0x7f, 0x82, 0xe6, 0x39, 0xc8, 0xce, 0xd0, 0xc8, 0xe5, 0x57, 0x16,
      0x72, 0x94, 0x9e, 0xfb, 0xed, 0x59, 0xde, 0x2e,
      // previous public encryption key
      0x8e, 0x3e, 0x33, 0x57, 0x3d, 0xd5, 0x3c, 0xe7, 0x29, 0xbc, 0x73, 0x90,
      0x7f, 0x83, 0x20, 0xee, 0xe9, 0x0b, 0x0a, 0x13, 0x05, 0xb1, 0x82, 0x85,
      0xab, 0x9d, 0xbe, 0x3f, 0xdb, 0x57, 0x2b, 0x71,
      // sealed key for previous user key
      0xf1, 0x28, 0xa8, 0x12, 0x03, 0x8e, 0x7c, 0x9c, 0x39, 0xad, 0x73, 0x21,
      0xa3, 0xee, 0x50, 0x53, 0xc1, 0x1d, 0xda, 0x76, 0xaf, 0xc8, 0xfd, 0x70,
      0x74, 0x5c, 0xbb, 0xd6, 0xb8, 0x7f, 0x8f, 0x6b, 0xe1, 0xaf, 0x36, 0x80,
      0x3f, 0xf3, 0xbc, 0xb2, 0xfb, 0x4e, 0xe1, 0x7d, 0xea, 0xbd, 0x19, 0x6b,
      0x8e, 0x3e, 0x33, 0x57, 0x3d, 0xd5, 0x3c, 0xe7, 0x29, 0xbc, 0x73, 0x90,
      0x7f, 0x83, 0x20, 0xee, 0x0e, 0xc0, 0x91, 0x63, 0xe7, 0xc2, 0x04, 0x69,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // length
      0x02,
      // recipient device id
      0xd0, 0xa8, 0x9e, 0xff, 0x7d, 0x59, 0x48, 0x3a, 0xee, 0x7c, 0xe4, 0x99,
      0x49, 0x4d, 0x1c, 0xd7, 0x87, 0x54, 0x41, 0xf5, 0xba, 0x51, 0xd7, 0x65,
      0xbf, 0x91, 0x45, 0x08, 0x03, 0xf1, 0xe9, 0xc7,
      // sealed user key for device
      0xe1, 0xaf, 0x36, 0x80, 0x3f, 0xf3, 0xbc, 0xb2, 0xfb, 0x4e, 0xe1, 0x7d,
      0xea, 0xbd, 0x19, 0x6b, 0x8e, 0x3e, 0x33, 0x57, 0x3d, 0xd5, 0x3c, 0xe7,
      0x29, 0xbc, 0x73, 0x90, 0x7f, 0x83, 0x20, 0xee, 0xf1, 0x28, 0xa8, 0x12,
      0x03, 0x8e, 0x7c, 0x9c, 0x39, 0xad, 0x73, 0x21, 0xa3, 0xee, 0x50, 0x53,
      0xc1, 0x1d, 0xda, 0x76, 0xaf, 0xc8, 0xfd, 0x70, 0x74, 0x5c, 0xbb, 0xd6,
      0xb8, 0x7f, 0x8f, 0x6b, 0x0e, 0xc0, 0x91, 0x63, 0xe7, 0xc2, 0x04, 0x69,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      // recipient device id
      0xd0, 0xa8, 0x9e, 0xff, 0x7d, 0x59, 0x48, 0x3a, 0xee, 0x7c, 0xe4, 0x99,
      0x49, 0x4d, 0x1c, 0xd7, 0x87, 0x54, 0x41, 0xf5, 0xba, 0x51, 0xd7, 0x65,
      0xbf, 0x91, 0x45, 0x08, 0x03, 0xf1, 0xe9, 0xc7,
      // sealed user key for device
      0xe1, 0xaf, 0x36, 0x80, 0x3f, 0xf3, 0xbc, 0xb2, 0xfb, 0x4e, 0xe1, 0x7d,
      0xea, 0xbd, 0x19, 0x6b, 0x8e, 0x3e, 0x33, 0x57, 0x3d, 0xd5, 0x3c, 0xe7,
      0x29, 0xbc, 0x73, 0x90, 0x7f, 0x83, 0x20, 0xee, 0xf1, 0x28, 0xa8, 0x12,
      0x03, 0x8e, 0x7c, 0x9c, 0x39, 0xad, 0x73, 0x21, 0xa3, 0xee, 0x50, 0x53,
      0xc1, 0x1d, 0xda, 0x76, 0xaf, 0xc8, 0xfd, 0x70, 0x74, 0x5c, 0xbb, 0xd6,
      0xb8, 0x7f, 0x8f, 0x6b, 0x0e, 0xc0, 0x91, 0x63, 0xe7, 0xc2, 0x04, 0x69,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    // clang-format on

    DeviceRevocation::v2::SealedKeysForDevices const sealedKeysForDevices{
        {DeviceId{serializedRecipientDeviceId},
         Crypto::SealedPrivateEncryptionKey{
             serializedSealedUserKeyForRecipient}},
        {DeviceId{serializedRecipientDeviceId},
         Crypto::SealedPrivateEncryptionKey{
             serializedSealedUserKeyForRecipient}}};
    DeviceRevocation::v2 const dr2{
        DeviceId{serializedDeviceId},
        Crypto::PublicEncryptionKey{serializedPublicEncryptionKey},
        Crypto::PublicEncryptionKey{serializedPreviousPublicEncryptionKey},
        Crypto::SealedPrivateEncryptionKey{serializedSealedKeyForPreviousUser},
        sealedKeysForDevices};

    CHECK(Serialization::deserialize<DeviceRevocation::v2>(
              serializedDeviceRevocation) == dr2);
    CHECK(Serialization::serialize(dr2) == serializedDeviceRevocation);
  }
}
