#include <Helpers/Errors.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Verification/Request.hpp>

#include <catch2/catch_test_macros.hpp>

using namespace Tanker;
using namespace Tanker::Verification;
using VVerification = Tanker::Verification::Verification;

TEST_CASE("makeRequestWithVerifChecks(Verification)")
{
  auto const userSecret = Tanker::Crypto::makeSymmetricKey();

  SECTION("accepts verifications ByEmail")
  {
    VVerification const verification = ByEmail{Email{"not empty"}, VerificationCode{"not empty"}};
    CHECK_NOTHROW(makeRequestWithVerif(verification, userSecret, std::nullopt, std::nullopt));
  }

  SECTION("accepts verifications ByPhoneNumber")
  {
    VVerification const verification = ByPhoneNumber{PhoneNumber{"not empty"}, VerificationCode{"not empty"}};
    CHECK_NOTHROW(makeRequestWithVerif(verification, userSecret, std::nullopt, std::nullopt));
  }

  SECTION("accepts verifications PreverifiedEmail")
  {
    VVerification const verification = PreverifiedEmail{"not empty"};
    CHECK_NOTHROW(makeRequestWithVerif(verification, userSecret, std::nullopt, std::nullopt));
  }

  SECTION("accepts verifications PreverifiedPhoneNumber")
  {
    VVerification const verification = PreverifiedPhoneNumber{"not empty"};
    CHECK_NOTHROW(makeRequestWithVerif(verification, userSecret, std::nullopt, std::nullopt));
  }

  SECTION("accepts verifications Passphrase")
  {
    VVerification const verification = Passphrase{"not empty"};
    CHECK_NOTHROW(makeRequestWithVerif(verification, userSecret, std::nullopt, std::nullopt));
  }

  SECTION("accepts verifications OidcIdToken")
  {
    VVerification const verification = OidcIdToken{"not empty", {}, {}};
    CHECK_NOTHROW(makeRequestWithVerif(verification, userSecret, std::nullopt, std::nullopt));
  }

  SECTION("accepts verifications VerificationKey")
  {
    VVerification const verification = VerificationKey{"not empty"};
    CHECK_NOTHROW(makeRequestWithVerif(verification, userSecret, std::nullopt, std::nullopt));
  }
}
