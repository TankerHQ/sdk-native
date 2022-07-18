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

tanker_future_t* tanker_admin_connect(char const* app_management_url,
                                      char const* app_management_token,
                                      char const* environment_name)
{
  return makeFuture(tc::async_resumable(
      [appManagementUrl = std::string(app_management_url),
       appManagementToken = std::string(app_management_token),
       environmentName = std::string(environment_name)]() -> tc::cotask<void*> {
        Crypto::init();
        Cacerts::init();
        const auto admin = new Admin::Client(
            appManagementUrl,
            appManagementToken,
            environmentName,
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
        const auto app = TC_AWAIT(admin->createTrustchain(name));
        using fmt::to_string;
        TC_RETURN(static_cast<void*>(new tanker_app_descriptor_t{
            duplicateString(name),
            duplicateString(to_string(app.id)),
            duplicateString(to_string(app.secret)),
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
  delete app;
}

tanker_future_t* tanker_admin_destroy(tanker_admin_t* admin)
{
  return makeFuture(tc::async(
      [admin = reinterpret_cast<Admin::Client*>(admin)] { delete admin; }));
}
