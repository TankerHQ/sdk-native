#include <Tanker/Functional/TrustchainFactory.hpp>

#include <Tanker/Init.hpp>
#include <Tanker/Network/ConnectionFactory.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <Helpers/Config.hpp>

#include <boost/filesystem/string_file.hpp>
#include <cppcodec/base64_rfc4648.hpp>
#include <nlohmann/json.hpp>

#include <memory>

namespace Tanker
{
namespace Functional
{
TrustchainFactory::TrustchainFactory()
  : _admin(std::make_unique<Admin::Admin>(
        Network::ConnectionFactory::create(TestConstants::trustchainUrl(),
                                           nonstd::nullopt),
        TestConstants::idToken()))
{
}

tc::cotask<TrustchainFactory::Ptr> TrustchainFactory::create()
{
  ::Tanker::init();
  auto factory = std::unique_ptr<TrustchainFactory>(new TrustchainFactory);
  TC_AWAIT(factory->_admin->start());
  TC_RETURN(std::move(factory));
}

tc::cotask<void> TrustchainFactory::deleteTrustchain(
    Tanker::Trustchain::TrustchainId const& id)
{
  TC_AWAIT(_admin->deleteTrustchain(id));
}

tc::cotask<Trustchain::Ptr> TrustchainFactory::createTrustchain(
    nonstd::optional<std::string> trustchainName,
    bool isTest,
    bool storePrivateKey)
{
  auto kp = Crypto::makeSignatureKeyPair();
  auto trustchainDefault = Tanker::Trustchain::TrustchainId{};
  Crypto::randomFill(trustchainDefault);
  auto trustchainId = TC_AWAIT(_admin->createTrustchain(
      trustchainName.value_or(
          cppcodec::base64_rfc4648::encode(trustchainDefault)),
      kp,
      isTest,
      storePrivateKey));
  TC_RETURN(Trustchain::make(TestConstants::trustchainUrl(), trustchainId, kp));
}

tc::cotask<Trustchain::Ptr> TrustchainFactory::useTrustchain(
    std::string configPath)
{
  auto config = loadTrustchainConfig(std::move(configPath));
  TC_RETURN(Trustchain::make(std::move(config)));
}

tc::cotask<VerificationCode> TrustchainFactory::getVerificationCode(
    Tanker::Trustchain::TrustchainId const& id, Email const& email)
{
  TC_RETURN(TC_AWAIT(this->_admin->getVerificationCode(id, email)));
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
