#pragma once

#include <Tanker/Test/Functional/Trustchain.hpp>

class TrustchainFixture
{
public:
  TrustchainFixture() : trustchain(Tanker::Test::Trustchain::getInstance())
  {
  }

protected:
  Tanker::Test::Trustchain& trustchain;
};
