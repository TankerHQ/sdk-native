#include <Tanker/Functional/TrustchainFactory.hpp>

#include <Helpers/JsonFile.hpp>
#include <Tanker/Admin/Client.hpp>
#include <Tanker/Init.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <Helpers/Config.hpp>

#include <mgs/base64.hpp>
#include <nlohmann/json.hpp>

#include <memory>

namespace Tanker
{
namespace Functional
{
TrustchainFactory::TrustchainFactory()
  : _admin(std::make_unique<Admin::Client>(
        TestConstants::admindUrl(),
        TestConstants::idToken(),
        tc::get_default_executor().get_io_service().get_executor()))
{
}

tc::cotask<TrustchainFactory::Ptr> TrustchainFactory::create()
{
  ::Tanker::init();
  auto factory = std::unique_ptr<TrustchainFactory>(new TrustchainFactory);
  TC_RETURN(std::move(factory));
}

tc::cotask<void> TrustchainFactory::deleteTrustchain(
    Tanker::Trustchain::TrustchainId const& id)
{
  TC_AWAIT(_admin->deleteTrustchain(id));
}

tc::cotask<Trustchain::Ptr> TrustchainFactory::createTrustchain(
    std::optional<std::string> trustchainName,
    bool isTest,
    bool storePrivateKey)
{
  auto kp = Crypto::makeSignatureKeyPair();
  auto trustchainDefault = Tanker::Trustchain::TrustchainId{};
  Crypto::randomFill(trustchainDefault);
  auto app = TC_AWAIT(_admin->createTrustchain(
      trustchainName.value_or(mgs::base64::encode(trustchainDefault)),
      kp,
      isTest));
  TC_RETURN(Trustchain::make(TestConstants::appdUrl(),
                             std::move(app.id),
                             std::move(app.authToken),
                             kp));
}

tc::cotask<void> TrustchainFactory::enableOidc(
    Tanker::Trustchain::TrustchainId const& id)
{
  auto const& oidcConfig = TestConstants::oidcConfig();
  Admin::AppUpdateOptions options{};
  options.oidcClientId = oidcConfig.clientId;
  options.oidcProvider = oidcConfig.provider;
  TC_AWAIT(_admin->update(id, options));
}

tc::cotask<void> TrustchainFactory::set2fa(
    Tanker::Trustchain::TrustchainId const& id, bool enable)
{
  Admin::AppUpdateOptions options{};
  options.sessionCertificates = enable;
  TC_AWAIT(_admin->update(id, options));
}

tc::cotask<void> TrustchainFactory::enablePreverifiedMethods(
    Tanker::Trustchain::TrustchainId const& id)
{
  Admin::AppUpdateOptions options;
  options.preverifiedVerification = true;
  TC_AWAIT(_admin->update(id, options));
}

tc::cotask<Trustchain::Ptr> TrustchainFactory::useTrustchain(
    std::string configPath)
{
  auto config = loadTrustchainConfig(std::move(configPath));
  TC_RETURN(Trustchain::make(std::move(config)));
}

void TrustchainFactory::saveTrustchainConfig(std::string const& path,
                                             TrustchainConfig const& config)
{
  saveJson(path, config);
}

TrustchainConfig TrustchainFactory::loadTrustchainConfig(
    std::string const& path)
{
  return loadJson(path).get<TrustchainConfig>();
}
}
}
