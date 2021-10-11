#include <ctanker/admin.h>

#include <Tanker/Admin/Client.hpp>
#include <Tanker/Cacerts/InitSsl.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Crypto/Init.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Types/Email.hpp>
#include <Tanker/Types/PhoneNumber.hpp>

#include <fmt/format.h>

#include <ctanker/async/private/CFuture.hpp>
#include <ctanker/private/Utils.hpp>

using namespace Tanker;
using namespace Tanker::Errors;

tanker_future_t* tanker_admin_connect(char const* url, char const* id_token)
{
  return makeFuture(tc::async_resumable(
      [url = std::string(url),
       idToken = std::string(id_token)]() -> tc::cotask<void*> {
        Crypto::init();
        Cacerts::init();
        const auto admin = new Admin::Client(
            url,
            idToken,
            tc::get_default_executor().get_io_service().get_executor());
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

tanker_future_t* tanker_admin_create_app_with_env_id(tanker_admin_t* admin,
                                                     char const* name,
                                                     char const* env_id)
{
  return makeFuture(
      tc::async_resumable([admin = reinterpret_cast<Admin::Client*>(admin),
                           name = std::string(name),
                           envId = std::string(env_id)]() -> tc::cotask<void*> {
        const auto appSignatureKeyPair(Crypto::makeSignatureKeyPair());
        const auto app = TC_AWAIT(
            admin->createTrustchain(name, appSignatureKeyPair, envId, true));
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
            mgs::base64::decode<Trustchain::TrustchainId>(appId)));
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

tanker_future_t* tanker_get_email_verification_code(char const* url,
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
            mgs::base64::decode<Trustchain::TrustchainId>(appId),
            authToken,
            Email{email}));
        TC_RETURN(static_cast<void*>(duplicateString(verifCode.string())));
      }));
}

tanker_future_t* tanker_get_sms_verification_code(char const* url,
                                                  char const* app_id,
                                                  char const* auth_token,
                                                  char const* user_phone_number)
{
  return makeFuture(tc::async_resumable(
      [url = std::string(url),
       appId = std::string(app_id),
       authToken = std::string(auth_token),
       phoneNumber = std::string(user_phone_number)]() -> tc::cotask<void*> {
        auto verifCode = TC_AWAIT(Admin::getVerificationCode(
            url,
            mgs::base64::decode<Trustchain::TrustchainId>(appId),
            authToken,
            PhoneNumber{phoneNumber}));
        TC_RETURN(static_cast<void*>(duplicateString(verifCode.string())));
      }));
}

tanker_future_t* tanker_admin_app_update(tanker_admin_t* admin,
                                         char const* app_id,
                                         tanker_app_update_options_t* coptions)
{
  if (coptions->version != 2)
    throw Exception(
        make_error_code(Errc::InvalidArgument),
        fmt::format("options version should be {:d} instead of {:d}",
                    1,
                    coptions->version));

  Admin::AppUpdateOptions appOptions{};
  if (coptions->oidc_client_id)
    appOptions.oidcClientId = coptions->oidc_client_id;
  if (coptions->oidc_client_provider)
    appOptions.oidcProvider = coptions->oidc_client_provider;
  if (coptions->session_certificates)
    appOptions.sessionCertificates = *coptions->session_certificates;
  return makeFuture(
      tc::async_resumable([admin = reinterpret_cast<Admin::Client*>(admin),
                           appID = std::string(app_id),
                           appOptions]() -> tc::cotask<void> {
        TC_AWAIT(admin->update(
            mgs::base64::decode<Trustchain::TrustchainId>(appID), appOptions));
      }));
}
