#include <Tanker/Compat/TrustchainFactory.hpp>

#include <Tanker/ConnectionFactory.hpp>
#include <Tanker/Init.hpp>
#include <Tanker/Types/TrustchainId.hpp>

#include <Helpers/Config.hpp>

#include <boost/filesystem/string_file.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <nlohmann/json.hpp>

#include <memory>

namespace Tanker
{
namespace Compat
{
TrustchainFactory::TrustchainFactory()
  : _admin(std::make_unique<Tanker::Admin>(
        Tanker::ConnectionFactory::create(
            Tanker::TestConstants::trustchainUrl(), nonstd::nullopt),
        Tanker::TestConstants::idToken()))
{
}

tc::future<TrustchainFactory> TrustchainFactory::create()
{
  return tc::async_resumable([]() -> tc::cotask<TrustchainFactory> {
    ::Tanker::init();
    auto factory = TrustchainFactory();
    TC_AWAIT(factory._admin->start());
    TC_RETURN(std::move(factory));
  });
}

tc::future<void> TrustchainFactory::deleteTrustchain(
    Tanker::TrustchainId const& id)
{
  return tc::async_resumable(
      [=]() -> tc::cotask<void> { TC_AWAIT(_admin->deleteTrustchain(id)); });
}

tc::future<Trustchain::Ptr> TrustchainFactory::createTrustchain(
    nonstd::optional<std::string> trustchainName, bool isTest)
{
  return tc::async_resumable([this,
                              trustchainName = std::move(trustchainName),
                              isTest]() -> tc::cotask<Trustchain::Ptr> {
    auto kp = Tanker::Crypto::makeSignatureKeyPair();
    auto trustchainId = TC_AWAIT(_admin->createTrustchain(
        trustchainName.value_or(to_string(_uuidGen())), kp, isTest));
    TC_RETURN(Trustchain::make(
        {Tanker::TestConstants::trustchainUrl(), trustchainId, kp}));
  });
}

tc::future<Trustchain::Ptr> TrustchainFactory::useTrustchain(
    std::string configPath)
{
  return tc::async_resumable(
      [path = std::move(configPath), this]() -> tc::cotask<Trustchain::Ptr> {
        auto config = loadTrustchainConfig(path);
        TC_RETURN(Trustchain::make(std::move(config), [this](Trustchain* tc) {
          this->deleteTrustchain(tc->id()).get();
          delete tc;
        }));
      });
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
  return nlohmann::json::parse(content);
}
}
}
