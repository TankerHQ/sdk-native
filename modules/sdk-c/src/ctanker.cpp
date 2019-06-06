#include <ctanker.h>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Format/Format.hpp>
#include <Tanker/Init.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Unlock/Methods.hpp>

#include <cppcodec/base64_rfc4648.hpp>
#include <tconcurrent/async.hpp>
#include <tconcurrent/thread_pool.hpp>

#include "CFuture.hpp"
#include "Utils.hpp"

#include <string>
#include <utility>

using namespace Tanker;
using namespace Tanker::Errors;

namespace
{
template <typename T>
nonstd::optional<T> nullableToOpt(char const* str)
{
  if (str && *str)
    return T(str);
  else
    return nonstd::nullopt;
}

Unlock::Verification cverificationToVerification(
    tanker_verification_t const* cverification)
{
  if (!cverification)
  {
    throw formatEx(
        Errc::InvalidArgument,
        "no verification method specified in the tanker_verification_t struct");
  }
  if (cverification->version != 1)
  {
    throw formatEx(Errc::InvalidArgument,
                   "unsupported tanker_verification_t struct version: {}",
                   cverification->version);
  }

  Unlock::Verification verification;
  switch (cverification->verification_method_type)
  {
  case TANKER_VERIFICATION_METHOD_EMAIL:
  {
    if (!cverification->email_verification.email ||
        !cverification->email_verification.verification_code)
      throw formatEx(Errc::InvalidArgument, "null field in email verification");
    verification = Unlock::EmailVerification{
        Email{cverification->email_verification.email},
        VerificationCode{cverification->email_verification.verification_code}};
    break;
  }
  case TANKER_VERIFICATION_METHOD_PASSPHRASE:
  {
    if (!cverification->passphrase)
      throw formatEx(Errc::InvalidArgument, "passphrase field is null");
    verification = Password{cverification->passphrase};
    break;
  }
  case TANKER_VERIFICATION_METHOD_VERIFICATION_KEY:
  {
    if (!cverification->verification_key)
      throw formatEx(Errc::InvalidArgument, "verification key is null");
    verification = VerificationKey{cverification->verification_key};
    break;
  }
  default:
    throw formatEx(Errc::InvalidArgument, "unknown verification type");
  }
  return verification;
}

void cVerificationMethodFromVerificationMethod(
    tanker_verification_method_t& c_verif_method,
    Unlock::VerificationMethod const& method)
{
  c_verif_method = TANKER_VERIFICATION_METHOD_INIT;
  if (method.holds_alternative<Password>())
    c_verif_method.verification_method_type =
        static_cast<uint8_t>(TANKER_VERIFICATION_METHOD_PASSPHRASE);
  else if (method.holds_alternative<VerificationKey>())
    c_verif_method.verification_method_type =
        static_cast<uint8_t>(TANKER_VERIFICATION_METHOD_VERIFICATION_KEY);
  else if (auto const email = method.get_if<Email>())
  {
    c_verif_method.verification_method_type =
        static_cast<uint8_t>(TANKER_VERIFICATION_METHOD_EMAIL);
    c_verif_method.email = duplicateString(email->c_str());
  }
  else
    throw AssertionError("unknown verification type");
}

#define STATIC_ENUM_CHECK(cval, cppval)           \
  static_assert(cval == static_cast<int>(cppval), \
                "enum values not in sync: " #cval " and " #cppval)

// Unlock

STATIC_ENUM_CHECK(TANKER_VERIFICATION_METHOD_EMAIL, Unlock::Method::Email);
STATIC_ENUM_CHECK(TANKER_VERIFICATION_METHOD_PASSPHRASE,
                  Unlock::Method::Password);
STATIC_ENUM_CHECK(TANKER_VERIFICATION_METHOD_VERIFICATION_KEY,
                  Unlock::Method::VerificationKey);
STATIC_ENUM_CHECK(TANKER_VERIFICATION_METHOD_LAST, Unlock::Method::Last);

static_assert(TANKER_VERIFICATION_METHOD_LAST == 3,
              "Please update the event assertions above if you added a new "
              "unlock methods");

// Status

STATIC_ENUM_CHECK(TANKER_STATUS_STOPPED, Status::Stopped);
STATIC_ENUM_CHECK(TANKER_STATUS_READY, Status::Ready);
STATIC_ENUM_CHECK(TANKER_STATUS_IDENTITY_REGISTRATION_NEEDED,
                  Status::IdentityRegistrationNeeded);
STATIC_ENUM_CHECK(TANKER_STATUS_IDENTITY_VERIFICATION_NEEDED,
                  Status::IdentityVerificationNeeded);

STATIC_ENUM_CHECK(TANKER_STATUS_LAST, Status::Last);

static_assert(
    TANKER_STATUS_LAST == 4,
    "Please update the status assertions above if you added a new status");

#undef STATIC_ENUM_CHECK
}

char const* tanker_version_string(void)
{
  return AsyncCore::version().c_str();
}

void tanker_init()
{
  Tanker::init();
}

tanker_future_t* tanker_create(const tanker_options_t* options)
{
  return makeFuture(tc::sync([&] {
    if (options == nullptr)
    {
      throw Exception(make_error_code(Errc::InvalidArgument),
                      "options is null");
    }
    if (options->version != 2)
    {
      throw Exception(
          make_error_code(Errc::InvalidArgument),
          fmt::format("Options version should be {:d} instead of {:d}",
                      options->version,
                      2));
    }
    if (options->trustchain_id == nullptr)
    {
      throw Exception(make_error_code(Errc::InvalidArgument),
                      "trustchain_id is null");
    }
    if (options->sdk_type == nullptr)
    {
      throw Exception(make_error_code(Errc::InvalidArgument),
                      "sdk_type is null");
    }
    if (options->sdk_version == nullptr)
    {
      throw Exception(make_error_code(Errc::InvalidArgument),
                      "sdk_version is null");
    }

    char const* url = options->trustchain_url;
    if (url == nullptr)
      url = "https://api.tanker.io";

    if (options->writable_path == nullptr)
    {
      throw Exception(make_error_code(Errc::InvalidArgument),
                      "writable_path is null");
    }

    return static_cast<void*>(new AsyncCore(
        url,
        {options->sdk_type,
         cppcodec::base64_rfc4648::decode<Trustchain::TrustchainId>(
             std::string(options->trustchain_id)),
         options->sdk_version},
        options->writable_path));
  }));
}

tanker_future_t* tanker_destroy(tanker_t* ctanker)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->destroy());
}

void tanker_set_log_handler(tanker_log_handler_t handler)
{
  AsyncCore::setLogHandler([handler](Tanker::Log::Record const& record) {
    tanker_log_record_t crecord = {
        record.category,
        static_cast<std::uint32_t>(record.level),
        record.file,
        record.line,
        record.message,
    };
    handler(&crecord);
  });
}

tanker_expected_t* tanker_event_connect(tanker_t* ctanker,
                                        enum tanker_event event,
                                        tanker_event_callback_t cb,
                                        void* data)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tc::sync([&] {
    switch (event)
    {
    case TANKER_EVENT_SESSION_CLOSED:
      return tanker->connectSessionClosed(
          [=, cb = std::move(cb)] { cb(nullptr, data); });
    case TANKER_EVENT_DEVICE_REVOKED:
      return tanker->connectDeviceRevoked(
          [=, cb = std::move(cb)] { cb(nullptr, data); });
    default:
      throw formatEx(Errc::InvalidArgument,
                     TFMT("unknown event: {:d}"),
                     static_cast<int>(event));
    }
  }));
}

tanker_expected_t* tanker_event_disconnect(tanker_t* ctanker,
                                           enum tanker_event event)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  switch (event)
  {
  case TANKER_EVENT_SESSION_CLOSED:
    tanker->disconnectSessionClosed();
    break;
  case TANKER_EVENT_DEVICE_REVOKED:
    tanker->disconnectDeviceRevoked();
    break;
  default:
    return makeFuture(
        tc::make_exceptional_future<void>(formatEx(Errc::InvalidArgument,
                                                   TFMT("unknown event: {:d}"),
                                                   static_cast<int>(event))));
  }
  return makeFuture(tc::make_ready_future());
}

tanker_future_t* tanker_start(tanker_t* ctanker, char const* identity)
{
  if (identity == nullptr)
    return makeFuture(tc::make_exceptional_future<void>(
        Exception(make_error_code(Errc::InvalidArgument), "identity is null")));

  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(
      tanker->start(std::string(identity))
          .and_then(tc::get_synchronous_executor(), [](auto status) {
            return reinterpret_cast<void*>(status);
          }));
}

tanker_future_t* tanker_register_identity(
    tanker_t* ctanker, tanker_verification_t const* cverification)
{
  return makeFuture(tc::sync([&] {
                      auto const verification =
                          cverificationToVerification(cverification);
                      auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
                      return tanker->registerIdentity(verification);
                    })
                        .unwrap());
}

tanker_future_t* tanker_verify_identity(
    tanker_t* ctanker, tanker_verification_t const* cverification)
{
  return makeFuture(tc::sync([&] {
                      auto const verification =
                          cverificationToVerification(cverification);
                      auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
                      return tanker->verifyIdentity(verification);
                    })
                        .unwrap());
}

tanker_future_t* tanker_stop(tanker_t* ctanker)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->stop());
}

enum tanker_status tanker_status(tanker_t* ctanker)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return static_cast<enum tanker_status>(tanker->status());
}

tanker_future_t* tanker_device_id(tanker_t* ctanker)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  auto fut = tanker->deviceId().and_then(
      tc::get_synchronous_executor(), [](auto const& deviceId) {
        return static_cast<void*>(duplicateString(deviceId.string()));
      });
  return makeFuture(std::move(fut));
}

tanker_future_t* tanker_get_device_list(tanker_t* ctanker)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->getDeviceList().and_then(
      tc::get_synchronous_executor(),
      [](std::vector<Device> const& deviceList) {
        auto* cDeviceList = new tanker_device_list_t;
        cDeviceList->count = deviceList.size();
        cDeviceList->devices = new tanker_device_list_elem_t[deviceList.size()];
        tanker_device_list_elem_t* cDevice = cDeviceList->devices;
        for (auto const& device : deviceList)
        {
          cDevice->device_id =
              duplicateString(cppcodec::base64_rfc4648::encode(device.id));
          cDevice->is_revoked = device.revokedAtBlkIndex.has_value();
          cDevice++;
        }
        return reinterpret_cast<void*>(cDeviceList);
      }));
}

tanker_future_t* tanker_generate_verification_key(tanker_t* ctanker)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->generateVerificationKey().and_then(
      tc::get_synchronous_executor(), [](auto uk) {
        return static_cast<void*>(duplicateString(uk.string()));
      }));
}

tanker_future_t* tanker_set_verification_method(
    tanker_t* ctanker, tanker_verification_t const* cverification)
{
  return makeFuture(tc::sync([&] {
                      auto const verification =
                          cverificationToVerification(cverification);
                      auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
                      return tanker->setVerificationMethod(verification);
                    })
                        .unwrap());
}

tanker_future_t* tanker_get_verification_methods(tanker_t* ctanker)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->getVerificationMethods().and_then(
      tc::get_synchronous_executor(),
      [](std::vector<Unlock::VerificationMethod> methods) {
        auto verifMethods = new tanker_verification_method_t[methods.size()];
        for (size_t i = 0; i < methods.size(); ++i)
        {
          cVerificationMethodFromVerificationMethod(verifMethods[i],
                                                    methods[i]);
        }
        auto verifMethodList = new tanker_verification_method_list;
        verifMethodList->count = methods.size();
        verifMethodList->methods = verifMethods;
        return reinterpret_cast<void*>(verifMethodList);
      }));
}

uint64_t tanker_encrypted_size(uint64_t clear_size)
{
  return AsyncCore::encryptedSize(clear_size);
}

tanker_expected_t* tanker_decrypted_size(uint8_t const* encrypted_data,
                                         uint64_t encrypted_size)
{
  return makeFuture(
      AsyncCore::decryptedSize(gsl::make_span(encrypted_data, encrypted_size))
          .and_then(tc::get_synchronous_executor(),
                    [](auto size) { return reinterpret_cast<void*>(size); }));
}

tanker_expected_t* tanker_get_resource_id(uint8_t const* encrypted_data,
                                          uint64_t encrypted_size)
{
  return makeFuture(
      AsyncCore::getResourceId(
          gsl::make_span(static_cast<uint8_t const*>(encrypted_data),
                         encrypted_size))
          .and_then(tc::get_synchronous_executor(), [](auto resId) {
            return static_cast<void*>(duplicateString(resId.string()));
          }));
}

tanker_future_t* tanker_encrypt(tanker_t* ctanker,
                                uint8_t* encrypted_data,
                                uint8_t const* data,
                                uint64_t data_size,
                                tanker_encrypt_options_t const* options)
{
  std::vector<SPublicIdentity> spublicIdentities{};
  std::vector<SGroupId> sgroupIds{};
  if (options)
  {
    if (options->version != 2)
    {
      return makeFuture(tc::make_exceptional_future<void>(
          formatEx(Errc::InvalidArgument,
                   "unsupported tanker_encrypt_options struct version")));
    }
    spublicIdentities =
        to_vector<SPublicIdentity>(options->recipient_public_identities,
                                   options->nb_recipient_public_identities);
    sgroupIds = to_vector<SGroupId>(options->recipient_gids,
                                    options->nb_recipient_gids);
  }
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->encrypt(encrypted_data,
                                    gsl::make_span(data, data_size),
                                    spublicIdentities,
                                    sgroupIds));
}

tanker_future_t* tanker_decrypt(tanker_t* ctanker,
                                uint8_t* decrypted_data,
                                uint8_t const* data,
                                uint64_t data_size)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(
      tanker->decrypt(decrypted_data, gsl::make_span(data, data_size)));
}

tanker_future_t* tanker_share(tanker_t* ctanker,
                              char const* const* recipient_public_identities,
                              uint64_t nb_recipient_public_identities,
                              char const* const* recipient_gids,
                              uint64_t nb_recipient_gids,
                              b64char const* const* resource_ids,
                              uint64_t nb_resource_ids)
{
  auto const spublicIdentities = to_vector<SPublicIdentity>(
      recipient_public_identities, nb_recipient_public_identities);
  auto const sgroupIds = to_vector<SGroupId>(recipient_gids, nb_recipient_gids);
  auto const resources = to_vector<SResourceId>(resource_ids, nb_resource_ids);
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);

  return makeFuture(tanker->share(resources, spublicIdentities, sgroupIds));
}

tanker_future_t* tanker_attach_provisional_identity(
    tanker_t* ctanker, char const* provisional_identity)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(
      tanker
          ->attachProvisionalIdentity(
              SSecretProvisionalIdentity{provisional_identity})
          .and_then(tc::get_synchronous_executor(),
                    [](AttachResult const& attachResult) {
                      auto cAttachResult = new tanker_attach_result_t;
                      cAttachResult->version = 1;
                      cAttachResult->method = nullptr;
                      cAttachResult->status =
                          static_cast<uint8_t>(attachResult.status);
                      if (attachResult.verificationMethod.has_value())
                      {
                        tanker_verification_method cMethod;
                        cVerificationMethodFromVerificationMethod(
                            cMethod, *attachResult.verificationMethod);
                        cAttachResult->method =
                            new tanker_verification_method(cMethod);
                      }
                      return reinterpret_cast<void*>(cAttachResult);
                    }));
}

tanker_future_t* tanker_verify_provisional_identity(
    tanker_t* ctanker, tanker_verification_t const* cverification)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  auto const verification = cverificationToVerification(cverification);

  return makeFuture(tanker->verifyProvisionalIdentity(verification));
}

tanker_future_t* tanker_revoke_device(tanker_t* ctanker,
                                      b64char const* device_id)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->revokeDevice(SDeviceId(device_id)));
}

void tanker_free_buffer(void const* buffer)
{
  free(const_cast<void*>(buffer));
}

void tanker_free_device_list(tanker_device_list_t* list)
{
  for (size_t i = 0; i < list->count; ++i)
    free(const_cast<b64char*>(list->devices[i].device_id));
  delete[] list->devices;
  delete list;
}

void tanker_free_verification_method_list(
    tanker_verification_method_list_t* methodList)
{
  for (size_t i = 0; i < methodList->count; ++i)
  {
    if (methodList->methods[i].verification_method_type ==
        TANKER_VERIFICATION_METHOD_EMAIL)
      free(const_cast<char*>(methodList->methods[i].email));
  }
  delete[] methodList->methods;
  delete methodList;
}

void tanker_free_attach_result(tanker_attach_result_t* result)
{
  if (result->method)
  {
    if (result->method->verification_method_type ==
        TANKER_VERIFICATION_METHOD_EMAIL)
      free(const_cast<char*>(result->method->email));
    delete result->method;
  }
  delete result;
}
