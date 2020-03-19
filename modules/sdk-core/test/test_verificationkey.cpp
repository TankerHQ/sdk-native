#include <Tanker/DeviceKeys.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/GhostDevice.hpp>

#include <Helpers/Buffers.hpp>
#include <Helpers/Errors.hpp>

#include <doctest.h>

using namespace std::string_literals;

using namespace Tanker;
using namespace Tanker::Trustchain;

TEST_CASE("it can convert a ghost device to unlock key")
{
  auto const ghostDevice = GhostDevice{
      make<Crypto::PrivateSignatureKey>("sigkey"),
      make<Crypto::PrivateEncryptionKey>("enckey"),
  };
  auto const gotGhostDevice = GhostDevice::create(
      VerificationKey{"eyJkZXZpY2VJZCI6IlpHVjJhV1FBQUFBQUFBQUFBQUFBQUF"
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
  SUBCASE("extract")
  {
    TANKER_CHECK_THROWS_WITH_CODE(GhostDevice::create(VerificationKey{"plop"}),
                                  Errors::Errc::InvalidVerification);
  }

  auto ghostDeviceKeys = DeviceKeys::create();
  auto const verificationKey =
      GhostDevice::create(ghostDeviceKeys).toVerificationKey();
  FAST_REQUIRE_UNARY_FALSE(verificationKey.empty());

  SUBCASE("generate")
  {
    REQUIRE_NOTHROW(GhostDevice::create(verificationKey));
    auto const gh = GhostDevice::create(verificationKey);
    FAST_CHECK_EQ(gh.privateEncryptionKey,
                  ghostDeviceKeys.encryptionKeyPair.privateKey);
    FAST_CHECK_EQ(gh.privateSignatureKey,
                  ghostDeviceKeys.signatureKeyPair.privateKey);
  }
}
