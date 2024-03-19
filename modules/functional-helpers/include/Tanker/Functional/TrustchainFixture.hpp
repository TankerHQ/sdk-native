#pragma once

#include <Tanker/Functional/Trustchain.hpp>
#include <Tanker/Functional/TrustchainFactory.hpp>
#include <Tanker/Identity/SecretIdentity.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/PhoneNumber.hpp>

namespace Tanker
{
namespace Functional
{
struct TrustchainFixtureSimple
{
  using PSCProvider = Functional::PSCProvider;

  Trustchain& trustchain;

  TrustchainFixtureSimple();
  static TrustchainFactory& trustchainFactory();

  static Trustchain& getTrustchain();

  static tc::cotask<void> setUp();
  static tc::cotask<void> tearDown();

  template <typename T>
  tc::cotask<VerificationCode> getVerificationCode(T const& target)
  {
    TC_RETURN(TC_AWAIT(trustchain.getVerificationCode(target)));
  }
  tc::cotask<void> attachProvisionalIdentity(AsyncCore& session, AppProvisionalUser const& prov);
  tc::cotask<void> injectStoreResourceKey(AsyncCore& session,
                                          Crypto::SimpleResourceId const& id,
                                          Crypto::SymmetricKey const& key);
  tc::cotask<VerificationKey> registerUser(Functional::User& user);
  Trustchain createOtherTrustchain();

  tc::cotask<void> enableOidc();

  tc::cotask<void> enableFakeOidc();
  tc::cotask<void> enablePSCOidc(Functional::PSCProvider const&);
  tc::cotask<void> enableUserEnrollment();
};

struct TrustchainFixture : TrustchainFixtureSimple
{
  User &alice, &bob, &charlie;
  Device &aliceDevice, &aliceDevice2, &bobDevice, &charlieDevice;
  AsyncCorePtr &aliceSession, &aliceSession2, &bobSession, &charlieSession;

  TrustchainFixture();
};
}
}
