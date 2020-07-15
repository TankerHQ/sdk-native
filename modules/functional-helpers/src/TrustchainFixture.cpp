#include <Tanker/Functional/TrustchainFixture.hpp>

#include <Tanker/Trustchain/TrustchainId.hpp>

#include <Helpers/Config.hpp>

namespace Tanker
{
namespace Functional
{
namespace
{
Trustchain::Ptr _trustchain;
TrustchainFactory::Ptr _trustchainFactory;

tc::cotask<void> deleteTrustchain()
{
  assert(_trustchain);
  // keep it because we will delete it
  auto const trustchainId = _trustchain->id;
  _trustchain.reset();
  TC_AWAIT(_trustchainFactory->deleteTrustchain(trustchainId));
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

TrustchainFactory& TrustchainFixture::trustchainFactory()
{
  return *_trustchainFactory;
}

Trustchain& TrustchainFixture::getTrustchain()
{
  assert(_trustchain);
  return *_trustchain;
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
  TC_RETURN(TC_AWAIT(Admin::getVerificationCode(TestConstants::trustchainUrl(),
                                                _trustchain->id,
                                                _trustchain->authToken,
                                                email)));
}

tc::cotask<void> TrustchainFixture::enableOidc()
{
  TC_AWAIT(trustchainFactory().enableOidc(trustchain.id));
}
}
}
