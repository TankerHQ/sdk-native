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
      TC_AWAIT(TrustchainFixtureSimple::trustchainFactory().createTrustchain(
          "sdk-native-functional-tests"));

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

TrustchainFixtureSimple::TrustchainFixtureSimple()
  : trustchain(*testState.trustchain)
{
}

TrustchainFactory& TrustchainFixtureSimple::trustchainFactory()
{
  return *_trustchainFactory;
}

Trustchain& TrustchainFixtureSimple::getTrustchain()
{
  return *testState.trustchain;
}

tc::cotask<void> TrustchainFixtureSimple::setUp()
{
  _trustchainFactory = TC_AWAIT(TrustchainFactory::create());
  TC_AWAIT(createTrustchain());
}

tc::cotask<void> TrustchainFixtureSimple::tearDown()
{
  TC_AWAIT(deleteTrustchain());
  _trustchainFactory.reset();
}

tc::cotask<VerificationKey> TrustchainFixtureSimple::registerUser(
    Functional::User& user)
{
  auto device0 = user.makeDevice();
  auto dummy = device0.createCore();
  TC_AWAIT(dummy->start(user.identity));
  auto verificationKey = TC_AWAIT(dummy->generateVerificationKey());
  if (dummy->status() != Status::IdentityRegistrationNeeded)
    throw std::runtime_error("Invalid status when registration users");
  TC_AWAIT(dummy->registerIdentity(VerificationKey{verificationKey}));
  TC_AWAIT(dummy->stop());
  TC_RETURN(verificationKey);
}

tc::cotask<void> TrustchainFixtureSimple::attachProvisionalIdentity(
    AsyncCore& session, AppProvisionalUser const& prov)
{
  TC_AWAIT(trustchain.attachProvisionalIdentity(session, prov));
}

Trustchain TrustchainFixtureSimple::createOtherTrustchain()
{
  Tanker::Trustchain::TrustchainId trustchainId;
  Crypto::randomFill(trustchainId);
  auto keyPair = Crypto::makeSignatureKeyPair();
  return Trustchain(
      "tcp://other.trustchain:1234", trustchainId, keyPair.privateKey);
}

tc::cotask<void> TrustchainFixtureSimple::enableOidc()
{
  TC_AWAIT(trustchainFactory().enableOidc(trustchain.id));
}

tc::cotask<void> TrustchainFixtureSimple::enablePSCOidc(
    PSCProvider const& provider)
{
  TC_AWAIT(trustchainFactory().enablePSCOidc(trustchain.id, provider));
}

tc::cotask<void> TrustchainFixtureSimple::enablePreverifiedMethods()
{
  TC_AWAIT(trustchainFactory().enablePreverifiedMethods(trustchain.id));
}

tc::cotask<void> TrustchainFixtureSimple::enableUserEnrollment()
{
  TC_AWAIT(trustchainFactory().setUserEnrollmentEnabled(trustchain.id));
}

TrustchainFixture::TrustchainFixture()
  : alice(*testState.alice),
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
}
}
