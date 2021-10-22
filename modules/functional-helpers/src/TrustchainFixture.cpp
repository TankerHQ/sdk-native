#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Types/Overloaded.hpp>

#include <Helpers/Config.hpp>

namespace Tanker
{
namespace Functional
{
namespace
{
TrustchainFactory::Ptr _trustchainFactory;

struct TrustchainTestState
{
  Trustchain::Ptr trustchain;
  std::optional<User> alice, bob, charlie;
  std::optional<Device> aliceDevice, aliceDevice2, bobDevice, charlieDevice;
  AsyncCorePtr aliceSession, aliceSession2, bobSession, charlieSession;
};
TrustchainTestState testState;

tc::cotask<void> createTrustchain()
{
  assert(!testState.trustchain);
  testState.trustchain =
      TC_AWAIT(TrustchainFixture::trustchainFactory().createTrustchain(
          "trustchain_functional_native", true));

  // If you add something here, you might need to delete it in
  // deleteTrustchain() below
  testState.alice = testState.trustchain->makeUser();
  testState.bob = testState.trustchain->makeUser();
  testState.charlie = testState.trustchain->makeUser();
  testState.aliceDevice = testState.alice->makeDevice();
  testState.aliceDevice2 = testState.alice->makeDevice();
  testState.bobDevice = testState.bob->makeDevice();
  testState.charlieDevice = testState.charlie->makeDevice();
  testState.aliceSession = TC_AWAIT(testState.aliceDevice->open());
  testState.aliceSession2 = TC_AWAIT(testState.aliceDevice2->open());
  testState.bobSession = TC_AWAIT(testState.bobDevice->open());
  testState.charlieSession = TC_AWAIT(testState.charlieDevice->open());
}

tc::cotask<void> deleteTrustchain()
{
  assert(testState.trustchain);

  // Destroy everything. We do not want to rely on static destruction, it
  // crashes on windows and I don't want to investigate.
  testState.aliceSession = testState.aliceSession2 = testState.bobSession =
      testState.charlieSession = nullptr;
  testState.aliceDevice = testState.aliceDevice2 = testState.bobDevice =
      testState.charlieDevice = std::nullopt;
  testState.alice = testState.bob = testState.charlie = std::nullopt;

  // keep it because we will delete it
  auto const trustchainId = testState.trustchain->id;
  testState.trustchain = nullptr;
  TC_AWAIT(_trustchainFactory->deleteTrustchain(trustchainId));
}
}

TrustchainFixture::TrustchainFixture()
  : trustchain(*testState.trustchain),
    alice(*testState.alice),
    bob(*testState.bob),
    charlie(*testState.charlie),
    aliceDevice(*testState.aliceDevice),
    aliceDevice2(*testState.aliceDevice2),
    bobDevice(*testState.bobDevice),
    charlieDevice(*testState.charlieDevice),
    aliceSession(testState.aliceSession),
    aliceSession2(testState.aliceSession2),
    bobSession(testState.bobSession),
    charlieSession(testState.charlieSession)
{
}

TrustchainFactory& TrustchainFixture::trustchainFactory()
{
  return *_trustchainFactory;
}

Trustchain& TrustchainFixture::getTrustchain()
{
  return *testState.trustchain;
}

tc::cotask<void> TrustchainFixture::setUp()
{
  _trustchainFactory = TC_AWAIT(TrustchainFactory::create());
  TC_AWAIT(createTrustchain());
}

tc::cotask<void> TrustchainFixture::tearDown()
{
  TC_AWAIT(deleteTrustchain());
  _trustchainFactory.reset();
}

tc::cotask<VerificationCode> TrustchainFixture::getVerificationCode(
    Email const& email)
{
  TC_RETURN(TC_AWAIT(Admin::getVerificationCode(TestConstants::trustchaindUrl(),
                                                trustchain.id,
                                                trustchain.authToken,
                                                email)));
}

tc::cotask<VerificationCode> TrustchainFixture::getVerificationCode(
    PhoneNumber const& phoneNumber)
{
  TC_RETURN(TC_AWAIT(Admin::getVerificationCode(TestConstants::trustchaindUrl(),
                                                trustchain.id,
                                                trustchain.authToken,
                                                phoneNumber)));
}

tc::cotask<void> TrustchainFixture::attachProvisionalIdentity(
    AsyncCore& session, AppProvisionalUser const& prov)
{
  auto const result =
      TC_AWAIT(session.attachProvisionalIdentity(prov.secretIdentity));
  if (result.status == Status::Ready)
    TC_RETURN();

  if (result.status != Status::IdentityVerificationNeeded)
    throw std::runtime_error("attachProvisionalIdentity: unexpected status!");

  auto const verif = TC_AWAIT(boost::variant2::visit(
      overloaded{
          [&](Email const& v) -> tc::cotask<Verification::Verification> {
            auto const verificationCode = TC_AWAIT(getVerificationCode(v));
            TC_RETURN(
                (Verification::ByEmail{v, VerificationCode{verificationCode}}));
          },
          [&](PhoneNumber const& v) -> tc::cotask<Verification::Verification> {
            auto const verificationCode = TC_AWAIT(getVerificationCode(v));
            TC_RETURN((Verification::ByPhoneNumber{
                v, VerificationCode{verificationCode}}));
          },
      },
      prov.value));
  TC_AWAIT(session.verifyProvisionalIdentity(verif));
}

tc::cotask<void> TrustchainFixture::enableOidc()
{
  TC_AWAIT(trustchainFactory().enableOidc(trustchain.id));
}

tc::cotask<void> TrustchainFixture::set2fa(bool enable)
{
  TC_AWAIT(trustchainFactory().set2fa(trustchain.id, enable));
}
}
}
