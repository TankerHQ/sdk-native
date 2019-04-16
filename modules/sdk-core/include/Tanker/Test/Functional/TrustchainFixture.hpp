#pragma once

#include <Tanker/Test/Functional/Trustchain.hpp>
#include <Tanker/Test/Functional/TrustchainFactory.hpp>

struct TrustchainFixture
{
  TrustchainFixture();
  static Tanker::Test::TrustchainFactory& trustchainFactory();

  static Tanker::Test::Trustchain& getTrustchain();
  Tanker::Test::Trustchain& trustchain;

  static tc::cotask<void> setUp();
  static tc::cotask<void> tearDown();

  tc::cotask<Tanker::VerificationCode> getVerificationCode(
      Tanker::Email const& email);
};
