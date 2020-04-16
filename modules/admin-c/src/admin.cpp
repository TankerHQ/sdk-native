#include <ctanker/admin.h>

#include <Tanker/Admin/Client.hpp>
#include <Tanker/Cacerts/InitSsl.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Crypto/Init.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>

#include <fmt/format.h>

#include <ctanker/async/private/CFuture.hpp>
#include <ctanker/private/Utils.hpp>

using namespace Tanker;

tanker_future_t* tanker_admin_connect(char const* url, char const* id_token)
{
  return makeFuture(tc::async_resumable(
      [url = std::string(url),
       idToken = std::string(id_token)]() -> tc::cotask<void*> {
        Crypto::init();
        Cacerts::init();
        const auto admin = new Admin::Client(url, idToken);
        TC_RETURN(static_cast<void*>(admin));
      }));
}

tanker_future_t* tanker_admin_create_app(tanker_admin_t* admin,
                                         char const* name)
{
  return makeFuture(
      tc::async_resumable([admin = reinterpret_cast<Admin::Client*>(admin),
                           name = std::string(name)]() -> tc::cotask<void*> {
        const auto appSignatureKeyPair(Crypto::makeSignatureKeyPair());
        const auto app =
            TC_AWAIT(admin->createTrustchain(name, appSignatureKeyPair, true));
        using fmt::to_string;
        TC_RETURN(static_cast<void*>(new tanker_app_descriptor_t{
            duplicateString(name),
            duplicateString(to_string(app.id)),
            duplicateString(app.authToken),
            duplicateString(to_string(appSignatureKeyPair.privateKey)),
            duplicateString(to_string(appSignatureKeyPair.publicKey)),
        }));
      }));
}

tanker_future_t* tanker_admin_delete_app(tanker_admin_t* admin,
                                         char const* app_id)
{
  return makeFuture(
      tc::async_resumable([admin = reinterpret_cast<Admin::Client*>(admin),
                           appId = std::string(app_id)]() -> tc::cotask<void> {
        TC_AWAIT(admin->deleteTrustchain(
            cppcodec::base64_rfc4648::decode<Trustchain::TrustchainId>(
                {appId})));
      }));
}

void tanker_admin_app_descriptor_free(tanker_app_descriptor_t* app)
{
  free(const_cast<char*>(app->name));
  free(const_cast<char*>(app->id));
  free(const_cast<char*>(app->private_key));
  free(const_cast<char*>(app->public_key));
  delete app;
}

tanker_future_t* tanker_admin_destroy(tanker_admin_t* admin)
{
  return makeFuture(tc::async(
      [admin = reinterpret_cast<Admin::Client*>(admin)] { delete admin; }));
}

tanker_future_t* tanker_get_verification_code(char const* url,
                                              char const* app_id,
                                              char const* auth_token,
                                              char const* user_email)
{
  return makeFuture(tc::async_resumable(
      [url = std::string(url),
       appId = std::string(app_id),
       authToken = std::string(auth_token),
       email = std::string(user_email)]() -> tc::cotask<void*> {
        auto verifCode = TC_AWAIT(Admin::getVerificationCode(
            url,
            cppcodec::base64_rfc4648::decode<Trustchain::TrustchainId>({appId}),
            authToken,
            Email{email}));
        TC_RETURN(static_cast<void*>(duplicateString(verifCode.string())));
      }));
}

tanker_future_t* tanker_admin_app_update(tanker_admin_t* admin,
                                         char const* app_id,
                                         char const* oidc_client_id,
                                         char const* oidc_provier)
{
  return makeFuture(tc::async_resumable(
      [admin = reinterpret_cast<Admin::Client*>(admin),
       appID = std::string(app_id),
       oidcClientId = std::string(oidc_client_id),
       oidcProvider = std::string(oidc_provier)]() -> tc::cotask<void> {
        TC_AWAIT(admin->update(
            cppcodec::base64_rfc4648::decode<Trustchain::TrustchainId>(appID),
            oidcClientId,
            oidcProvider));
      }));
}
