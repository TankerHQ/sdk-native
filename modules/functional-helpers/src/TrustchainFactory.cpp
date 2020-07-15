#include <Tanker/Functional/TrustchainFactory.hpp>

#include <Tanker/Admin/Client.hpp>
#include <Tanker/Init.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <Helpers/Config.hpp>

#include <boost/filesystem/string_file.hpp>
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
  TC_RETURN(Trustchain::make(TestConstants::trustchainUrl(),
                             std::move(app.id),
                             std::move(app.authToken),
                             kp));
}

tc::cotask<void> TrustchainFactory::enableOidc(
    Tanker::Trustchain::TrustchainId const& id)
{
  auto const& oidcConfig = TestConstants::oidcConfig();
  TC_AWAIT(_admin->update(id, oidcConfig.clientId, oidcConfig.provider));
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
  boost::filesystem::save_string_file(path, nlohmann::json(config).dump());
}

TrustchainConfig TrustchainFactory::loadTrustchainConfig(
    std::string const& path)
{
  std::string content;
  boost::filesystem::load_string_file(path, content);
  return nlohmann::json::parse(content).get<TrustchainConfig>();
}
}
}
