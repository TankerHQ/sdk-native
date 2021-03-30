#pragma once

#include <Tanker/Functional/Trustchain.hpp>
#include <Tanker/Functional/TrustchainFactory.hpp>
#include <Tanker/Types/Email.hpp>

namespace Tanker
{
namespace Functional
{
struct TrustchainFixture
{
  TrustchainFixture();
  static TrustchainFactory& trustchainFactory();

  static Trustchain& getTrustchain();
  Trustchain& trustchain;

  static tc::cotask<void> setUp();
  static tc::cotask<void> tearDown();

  tc::cotask<VerificationCode> getVerificationCode(Email const& email);
  tc::cotask<void> enableOidc();
  tc::cotask<void> enable2fa();
};
}
}
