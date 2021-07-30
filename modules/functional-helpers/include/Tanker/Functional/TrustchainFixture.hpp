#pragma once

#include <Tanker/Functional/Trustchain.hpp>
#include <Tanker/Functional/TrustchainFactory.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/PhoneNumber.hpp>

namespace Tanker
{
namespace Functional
{
struct TrustchainFixture
{
  Trustchain& trustchain;
  User &alice, &bob, &charlie;
  Device &aliceDevice, &aliceDevice2, &bobDevice, &charlieDevice;
  AsyncCorePtr &aliceSession, &aliceSession2, &bobSession, &charlieSession;

  TrustchainFixture();
  static TrustchainFactory& trustchainFactory();

  static Trustchain& getTrustchain();

  static tc::cotask<void> setUp();
  static tc::cotask<void> tearDown();

  tc::cotask<VerificationCode> getVerificationCode(Email const& email);
  tc::cotask<VerificationCode> getVerificationCode(
      PhoneNumber const& phoneNumber);
  tc::cotask<void> attachProvisionalIdentity(AsyncCore& session,
                                             AppProvisionalUser const& prov);
  tc::cotask<void> enableOidc();
  tc::cotask<void> enable2fa();
};
}
}
