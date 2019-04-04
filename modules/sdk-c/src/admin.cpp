#include <ctanker/admin.h>
#include <ctanker/ctanker.h>

#include <Tanker/Admin.hpp>
#include <Tanker/ConnectionFactory.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Init.hpp>
#include <Tanker/Types/TrustchainId.hpp>

#include "CFuture.hpp"
#include "Utils.hpp"

using namespace Tanker;

tanker_future_t* tanker_admin_connect(char const* trustchain_url,
                                      char const* id_token)
{
  return makeFuture(tc::async_resumable(
      [trustchainUrl = std::string(trustchain_url),
       idToken = std::string(id_token)]() -> tc::cotask<void*> {
        Tanker::init();
        const auto admin = new Admin(
            ConnectionFactory::create(trustchainUrl, nonstd::nullopt), idToken);
        TC_AWAIT(admin->start());
        TC_RETURN(static_cast<void*>(admin));
      }));
}

tanker_future_t* tanker_admin_create_trustchain(tanker_admin_t* admin,
                                                char const* name)
{
  return makeFuture(tc::async_resumable([admin =
                                             reinterpret_cast<Admin*>(admin),
                                         name = std::string(
                                             name)]() -> tc::cotask<void*> {
    const auto trustchainSignatureKeyPair(Crypto::makeSignatureKeyPair());
    const auto trustchainId = TC_AWAIT(
        admin->createTrustchain(name, trustchainSignatureKeyPair, true));
    TC_RETURN(static_cast<void*>(new tanker_trustchain_descriptor_t{
        duplicateString(name),
        duplicateString(base64::encode(trustchainId)),
        duplicateString(base64::encode(trustchainSignatureKeyPair.privateKey)),
        duplicateString(base64::encode(trustchainSignatureKeyPair.publicKey)),
    }));
  }));
}

tanker_future_t* tanker_admin_delete_trustchain(tanker_admin_t* admin,
                                                char const* trustchain_id)
{
  return makeFuture(tc::async_resumable(
      [admin = reinterpret_cast<Admin*>(admin),
       trustchainId = std::string(trustchain_id)]() -> tc::cotask<void> {
        TC_AWAIT(admin->deleteTrustchain(
            base64::decode<TrustchainId>({trustchainId})));
      }));
}

void tanker_admin_trustchain_descriptor_free(
    tanker_trustchain_descriptor_t* trustchain)
{
  tanker_free_buffer(const_cast<char*>(trustchain->name));
  tanker_free_buffer(const_cast<char*>(trustchain->id));
  tanker_free_buffer(const_cast<char*>(trustchain->private_key));
  tanker_free_buffer(const_cast<char*>(trustchain->public_key));
  delete trustchain;
}

tanker_future_t* tanker_admin_destroy(tanker_admin_t* admin)
{
  return makeFuture(
      tc::async([admin = reinterpret_cast<Admin*>(admin)] { delete admin; }));
}

tanker_future_t* tanker_admin_get_verification_code(
    tanker_admin_t* admin, char const* trustchain_id, char const* user_email)
{
  return makeFuture(tc::async_resumable(
      [admin = reinterpret_cast<Admin*>(admin),
       trustchainId = std::string(trustchain_id),
       email = std::string(user_email)]() -> tc::cotask<void*> {
         auto verifCode = TC_AWAIT(admin->getVerificationCode(base64::decode<TrustchainId>({trustchainId}), Email{email}));
         TC_RETURN(static_cast<void*>(duplicateString(verifCode.string())));
         }
      ));
}
