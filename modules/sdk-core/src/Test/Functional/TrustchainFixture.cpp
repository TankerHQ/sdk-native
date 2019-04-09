#include <Tanker/Test/Functional/TrustchainFixture.hpp>

namespace
{
Tanker::Test::Trustchain::Ptr _trustchain;
Tanker::Test::TrustchainFactory::Ptr _trustchainFactory;

tc::cotask<void> deleteTrustchain()
{
  assert(_trustchain);
  _trustchainFactory->deleteTrustchain(_trustchain->id);
  _trustchain.reset();
}

tc::cotask<void> createTrustchain()
{
  assert(!_trustchain);
  _trustchain =
      TC_AWAIT(TrustchainFixture::trustchainFactory().createTrustchain(
          "trustchain_functional_native", true));
}
}

TrustchainFixture::TrustchainFixture() : trustchain(getTrustchain())
{
  trustchain.reuseCache();
}

Tanker::Test::TrustchainFactory& TrustchainFixture::trustchainFactory()
{
  return *_trustchainFactory;
}

Tanker::Test::Trustchain& TrustchainFixture::getTrustchain()
{
  assert(_trustchain);
  return *_trustchain;
}

tc::cotask<void> TrustchainFixture::setUp()
{
  _trustchainFactory = TC_AWAIT(Tanker::Test::TrustchainFactory::create());
  TC_AWAIT(createTrustchain());
}

tc::cotask<void> TrustchainFixture::tearDown()
{
  TC_AWAIT(deleteTrustchain());
  _trustchainFactory.reset();
}

tc::cotask<Tanker::VerificationCode> TrustchainFixture::getVerificationCode(
    Tanker::Email const& email)
{
  TC_RETURN(
      TC_AWAIT(trustchainFactory().getVerificationCode(trustchain.id, email)));
}
