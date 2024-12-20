#include <Tanker/Functional/TrustchainFactory.hpp>

#include <Helpers/JsonFile.hpp>
#include <Tanker/Admin/Client.hpp>
#include <Tanker/Crypto/PrivateSignatureKey.hpp>
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
        TestConstants::appManagementUrl(), TestConstants::appManagementToken(), TestConstants::environmentName()))
{
}

tc::cotask<TrustchainFactory::Ptr> TrustchainFactory::create()
{
  ::Tanker::init();
  auto factory = std::unique_ptr<TrustchainFactory>(new TrustchainFactory);
  TC_RETURN(std::move(factory));
}

tc::cotask<void> TrustchainFactory::deleteTrustchain(Tanker::Trustchain::TrustchainId const& id)
{
  TC_AWAIT(_admin->deleteTrustchain(id));
}

tc::cotask<Trustchain::Ptr> TrustchainFactory::createTrustchain(std::string const& name)
{
  auto const app = TC_AWAIT(_admin->createTrustchain(name));
  TC_RETURN(Trustchain::make(TestConstants::appdUrl(), std::move(app.id), std::move(app.secret)));
}

tc::cotask<void> TrustchainFactory::enableOidc(Tanker::Trustchain::TrustchainId const& id)
{
  auto const& oidcConfig = TestConstants::oidcConfig();
  Admin::OidcConfiguration adminOidcConf{};
  adminOidcConf.displayName = oidcConfig.displayName;
  adminOidcConf.clientId = oidcConfig.clientId;
  adminOidcConf.issuer = oidcConfig.issuer;
  adminOidcConf.oidcProviderGroupId = "qYjh0nn2C5s8mj9d-F4Oy8UhFqVTNZpnuwE55lWHV7Y";

  Admin::AppUpdateOptions options{};
  options.oidcProviders = {adminOidcConf};
  TC_AWAIT(_admin->update(id, options));
}

tc::cotask<void> TrustchainFactory::enableFakeOidc(Tanker::Trustchain::TrustchainId const& id)
{
  auto const& fakeOidcIssuerUrl = TestConstants::oidcConfig().fakeOidcIssuerUrl;
  Admin::AppUpdateOptions options{};

  auto fakeOidcProviderGroupID = "BxFm1n2_wR2V02gbO-tRK68rTiOwPps0L_hGjxkHofM";
  auto wrongFakeOidcProviderGroupID = "s5XXhLYMKOn6aMKmtdu1590Nyri0XEEHyKMWueiieOk";
  options.oidcProviders = std::vector<Admin::OidcConfiguration>{
    { "fake-oidc",  "tanker", fakeOidcIssuerUrl + "/main", fakeOidcProviderGroupID},
    { "fake-oidc/alt",  "tanker", fakeOidcIssuerUrl + "/alt", fakeOidcProviderGroupID},
    { "fake-oidc/wrong-group",  "tanker", fakeOidcIssuerUrl + "/wrong-group", wrongFakeOidcProviderGroupID},
  };
  TC_AWAIT(_admin->update(id, options));
}

std::string to_string(PSCProvider provider)
{
  switch (provider)
  {
  case PSCProvider::PSC_BAS:
    return "pro-sante-bas";
  case PSCProvider::PSC_BAS_NO_EXPIRY:
    return "pro-sante-bas-no-expiry";
  default:
    throw std::logic_error("unknown PSC provider");
  }
}

tc::cotask<void> TrustchainFactory::enablePSCOidc(Tanker::Trustchain::TrustchainId const& id,
                                                  PSCProvider const& provider)
{
  Admin::OidcConfiguration adminOidcConf{};
  adminOidcConf.displayName = to_string(provider);
  adminOidcConf.clientId = "doctolib-dev";
  adminOidcConf.issuer = "https://auth.bas.psc.esante.gouv.fr/auth/realms/esante-wallet";
  adminOidcConf.oidcProviderGroupId = "m-DsT9cPgBqoQJPFI3IOMBPobofKvjzXEPA6kOfnCuA";

  Admin::AppUpdateOptions options{};
  options.oidcProviders = {adminOidcConf};
  TC_AWAIT(_admin->update(id, options));
}

tc::cotask<Trustchain::Ptr> TrustchainFactory::useTrustchain(std::string configPath)
{
  auto config = loadTrustchainConfig(std::move(configPath));
  TC_RETURN(Trustchain::make(std::move(config)));
}

void TrustchainFactory::saveTrustchainConfig(std::string const& path, TrustchainConfig const& config)
{
  saveJson(path, config);
}

TrustchainConfig TrustchainFactory::loadTrustchainConfig(std::string const& path)
{
  return loadJson(path).get<TrustchainConfig>();
}
}
}
