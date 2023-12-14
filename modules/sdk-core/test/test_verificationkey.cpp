#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/GhostDevice.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <catch2/catch_test_macros.hpp>

using namespace std::string_literals;

using namespace Tanker;
using namespace Tanker::Trustchain;

TEST_CASE("it can convert a ghost device to unlock key")
{
  auto const ghostDevice = GhostDevice{
      make<Crypto::PrivateSignatureKey>("sigkey"),
      make<Crypto::PrivateEncryptionKey>("enckey"),
  };
  auto const gotGhostDevice =
      GhostDevice::create(VerificationKey{"eyJkZXZpY2VJZCI6IlpHVjJhV1FBQUFBQUFBQUFBQUFBQUF"
                                          "BQUFBQUFBQUFBQUFBQUFBQU"
                                          "FBQUE9IiwicHJpdmF0ZVNpZ25hdHVyZUtleSI6ImMybG5hM"
                                          "lY1QUFBQUFBQUFBQUFBQUFB"
                                          "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUF"
                                          "BQUFBQUFBQUFBQUFBQUFBQU"
                                          "FBQUFBQUFBQUFBPT0iLCJwcml2YXRlRW5jcnlwdGlvbktle"
                                          "SI6IlpXNWphMlY1QUFBQUFB"
                                          "QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE9In0="});
  CHECK(ghostDevice == gotGhostDevice);
}

TEST_CASE("verificationKey")
{
  SECTION("extract")
  {
    TANKER_CHECK_THROWS_WITH_CODE(GhostDevice::create(VerificationKey{"plop"}), Errors::Errc::InvalidVerification);
  }

  auto ghostDeviceKeys = DeviceKeys::create();
  auto const verificationKey = GhostDevice::create(ghostDeviceKeys).toVerificationKey();
  REQUIRE(!verificationKey.empty());

  SECTION("generate")
  {
    REQUIRE_NOTHROW(GhostDevice::create(verificationKey));
    auto const gh = GhostDevice::create(verificationKey);
    CHECK(gh.privateEncryptionKey == ghostDeviceKeys.encryptionKeyPair.privateKey);
    CHECK(gh.privateSignatureKey == ghostDeviceKeys.signatureKeyPair.privateKey);
  }
}
