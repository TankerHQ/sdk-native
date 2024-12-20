#include <ctanker.h>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Padding.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Init.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Utils.hpp>
#include <Tanker/Verification/Methods.hpp>

#include <boost/algorithm/hex.hpp>
#include <mgs/base64.hpp>
#include <tconcurrent/async.hpp>
#include <tconcurrent/thread_pool.hpp>

#include <ctanker/async/private/CFuture.hpp>
#include <ctanker/private/CDataStore.hpp>
#include <ctanker/private/CNetwork.hpp>
#include <ctanker/private/Utils.hpp>

#include "CPadding.hpp"

#include <optional>
#include <string>
#include <utility>

using namespace Tanker;
using namespace Tanker::Errors;

namespace
{
template <typename T>
std::optional<T> nullableToOpt(char const* str)
{
  if (str && *str)
    return T(str);
  else
    return std::nullopt;
}

Verification::Verification cverificationToVerification(tanker_verification_t const* cverification)
{
  if (!cverification)
  {
    throw formatEx(Errc::InvalidArgument, "no verification method specified in the tanker_verification_t struct");
  }
  if (cverification->version != 9)
  {
    throw formatEx(
        Errc::InvalidArgument, "unsupported tanker_verification_t struct version: {}", cverification->version);
  }

  Verification::Verification verification;
  switch (cverification->verification_method_type)
  {
  case TANKER_VERIFICATION_METHOD_EMAIL: {
    if (!cverification->email_verification.email || !cverification->email_verification.verification_code)
      throw formatEx(Errc::InvalidArgument, "null field in email verification");
    verification = Verification::ByEmail{Email{cverification->email_verification.email},
                                         VerificationCode{cverification->email_verification.verification_code}};
    break;
  }
  case TANKER_VERIFICATION_METHOD_PASSPHRASE: {
    if (!cverification->passphrase)
      throw formatEx(Errc::InvalidArgument, "passphrase field is null");
    verification = Passphrase{cverification->passphrase};
    break;
  }
  case TANKER_VERIFICATION_METHOD_E2E_PASSPHRASE: {
    if (!cverification->e2e_passphrase)
      throw formatEx(Errc::InvalidArgument, "e2e_passphrase field is null");
    verification = E2ePassphrase{cverification->e2e_passphrase};
    break;
  }
  case TANKER_VERIFICATION_METHOD_VERIFICATION_KEY: {
    if (!cverification->verification_key)
      throw formatEx(Errc::InvalidArgument, "verification key is null");
    verification = VerificationKey{cverification->verification_key};
    break;
  }
  case TANKER_VERIFICATION_METHOD_OIDC_ID_TOKEN: {
    if (!cverification->oidc_id_token)
      throw formatEx(Errc::InvalidArgument, "oidc id token field is null");
    verification = OidcIdToken{cverification->oidc_id_token, {}, {}};
    break;
  }
  case TANKER_VERIFICATION_METHOD_PHONE_NUMBER: {
    if (!cverification->phone_number_verification.phone_number ||
        !cverification->phone_number_verification.verification_code)
      throw formatEx(Errc::InvalidArgument, "null field in phone number verification");
    verification =
        Verification::ByPhoneNumber{PhoneNumber{cverification->phone_number_verification.phone_number},
                                    VerificationCode{cverification->phone_number_verification.verification_code}};
    break;
  }
  case TANKER_VERIFICATION_METHOD_PREVERIFIED_EMAIL: {
    if (!cverification->preverified_email)
      throw formatEx(Errc::InvalidArgument, "preverified email field is null");
    verification = PreverifiedEmail{cverification->preverified_email};
    break;
  }
  case TANKER_VERIFICATION_METHOD_PREVERIFIED_PHONE_NUMBER: {
    if (!cverification->preverified_phone_number)
      throw formatEx(Errc::InvalidArgument, "preverified phone number field is null");
    verification = PreverifiedPhoneNumber{cverification->preverified_phone_number};
    break;
  }
  case TANKER_VERIFICATION_METHOD_PREVERIFIED_OIDC: {
    if (!cverification->preverified_oidc_verification.subject)
      throw formatEx(Errc::InvalidArgument, "oidc subject field is null");
    if (!cverification->preverified_oidc_verification.provider_id)
      throw formatEx(Errc::InvalidArgument, "oidc provider id field is null");
    verification = PreverifiedOidc{cverification->preverified_oidc_verification.provider_id,
                                   cverification->preverified_oidc_verification.subject};
    break;
  }
  case TANKER_VERIFICATION_METHOD_OIDC_AUTHORIZATION_CODE: {
    if (!cverification->oidc_authorization_code_verification.provider_id)
      throw formatEx(Errc::InvalidArgument, "oidc provider id field is null");
    if (!cverification->oidc_authorization_code_verification.authorization_code)
      throw formatEx(Errc::InvalidArgument, "oidc authorization_code field is null");
    if (!cverification->oidc_authorization_code_verification.state)
      throw formatEx(Errc::InvalidArgument, "oidc state field is null");
    verification = OidcAuthorizationCode{cverification->oidc_authorization_code_verification.provider_id,
                                         cverification->oidc_authorization_code_verification.authorization_code,
                                         cverification->oidc_authorization_code_verification.state};
    break;
  }
  case TANKER_VERIFICATION_METHOD_PREHASHED_AND_ENCRYPTED_PASSPHRASE: {
    if (!cverification->prehashed_and_encrypted_passphrase)
      throw formatEx(Errc::InvalidArgument, "prehashed_and_encrypted_passphrase field is null");
    verification = PrehashedAndEncryptedPassphrase{cverification->prehashed_and_encrypted_passphrase};
    break;
  }
  default:
    throw formatEx(Errc::InvalidArgument, "unknown verification type");
  }
  return verification;
}

std::vector<Verification::Verification> cverificationListToVerifications(
    tanker_verification_list_t const* cverifications)
{
  return ranges::make_subrange(cverifications->verifications, cverifications->verifications + cverifications->count) |
         ranges::views::transform(
             [](tanker_verification_t const& cverification) { return cverificationToVerification(&cverification); }) |
         ranges::to<std::vector>;
}

void cVerificationMethodFromVerificationMethod(tanker_verification_method_t& c_verif_method,
                                               Verification::VerificationMethod const& method)
{
  c_verif_method.version = 2;
  c_verif_method.value1 = nullptr;
  c_verif_method.value2 = nullptr;
  if (method.holds_alternative<Passphrase>())
    c_verif_method.verification_method_type = static_cast<uint8_t>(TANKER_VERIFICATION_METHOD_PASSPHRASE);
  else if (method.holds_alternative<E2ePassphrase>())
    c_verif_method.verification_method_type = static_cast<uint8_t>(TANKER_VERIFICATION_METHOD_E2E_PASSPHRASE);
  else if (auto const oidc = method.get_if<OidcIdToken>())
  {
    c_verif_method.verification_method_type = static_cast<uint8_t>(TANKER_VERIFICATION_METHOD_OIDC_ID_TOKEN);
    c_verif_method.value1 = duplicateString(oidc->provider_id);
    c_verif_method.value2 = duplicateString(oidc->provider_display_name);
  }
  else if (method.holds_alternative<VerificationKey>())
    c_verif_method.verification_method_type = static_cast<uint8_t>(TANKER_VERIFICATION_METHOD_VERIFICATION_KEY);
  else if (auto const email = method.get_if<Email>())
  {
    c_verif_method.verification_method_type = static_cast<uint8_t>(TANKER_VERIFICATION_METHOD_EMAIL);
    c_verif_method.value1 = duplicateString(email->c_str());
  }
  else if (auto const phoneNumber = method.get_if<PhoneNumber>())
  {
    c_verif_method.verification_method_type = static_cast<uint8_t>(TANKER_VERIFICATION_METHOD_PHONE_NUMBER);
    c_verif_method.value1 = duplicateString(phoneNumber->c_str());
  }
  else if (auto const preverifiedEmail = method.get_if<PreverifiedEmail>())
  {
    c_verif_method.verification_method_type = static_cast<uint8_t>(TANKER_VERIFICATION_METHOD_PREVERIFIED_EMAIL);
    c_verif_method.value1 = duplicateString(preverifiedEmail->c_str());
  }
  else if (auto const preverifiedPhoneNumber = method.get_if<PreverifiedPhoneNumber>())
  {
    c_verif_method.verification_method_type = static_cast<uint8_t>(TANKER_VERIFICATION_METHOD_PREVERIFIED_PHONE_NUMBER);
    c_verif_method.value1 = duplicateString(preverifiedPhoneNumber->c_str());
  }
  else
    throw AssertionError("unknown verification type");
}

Tanker::Core::VerifyWithToken withTokenFromVerifOptions(tanker_verification_options_t const* cverif_opts)
{
  using VerifyWithToken = Tanker::Core::VerifyWithToken;

  if (!cverif_opts)
    return VerifyWithToken::No;
  if (cverif_opts->version != 2)
    throw Exception(make_error_code(Errc::InvalidArgument),
                    fmt::format("options version should be {:d} instead of {:d}", 2, cverif_opts->version));

  bool withToken = cverif_opts->with_session_token;
  return withToken ? VerifyWithToken::Yes : VerifyWithToken::No;
}

Tanker::Core::AllowE2eMethodSwitch allowE2eMethodSwitchFromVerifOptions(
    tanker_verification_options_t const* cverif_opts)
{
  using AllowE2eMethodSwitch = Tanker::Core::AllowE2eMethodSwitch;

  if (!cverif_opts)
    return AllowE2eMethodSwitch::No;
  if (cverif_opts->version != 2)
    throw Exception(make_error_code(Errc::InvalidArgument),
                    fmt::format("options version should be {:d} instead of {:d}", 2, cverif_opts->version));

  bool allowE2eMethodSwitch = cverif_opts->allow_e2e_method_switch;
  return allowE2eMethodSwitch ? AllowE2eMethodSwitch::Yes : AllowE2eMethodSwitch::No;
}

#define STATIC_ENUM_CHECK(cval, cppval) \
  static_assert(cval == static_cast<int>(cppval), "enum values not in sync: " #cval " and " #cppval)

// Unlock

STATIC_ENUM_CHECK(TANKER_VERIFICATION_METHOD_EMAIL, Verification::Method::Email);
STATIC_ENUM_CHECK(TANKER_VERIFICATION_METHOD_PASSPHRASE, Verification::Method::Passphrase);
STATIC_ENUM_CHECK(TANKER_VERIFICATION_METHOD_E2E_PASSPHRASE, Verification::Method::E2ePassphrase);
STATIC_ENUM_CHECK(TANKER_VERIFICATION_METHOD_VERIFICATION_KEY, Verification::Method::VerificationKey);
STATIC_ENUM_CHECK(TANKER_VERIFICATION_METHOD_OIDC_ID_TOKEN, Verification::Method::OidcIdToken);
STATIC_ENUM_CHECK(TANKER_VERIFICATION_METHOD_PHONE_NUMBER, Verification::Method::PhoneNumber);
STATIC_ENUM_CHECK(TANKER_VERIFICATION_METHOD_PREVERIFIED_EMAIL, Verification::Method::PreverifiedEmail);
STATIC_ENUM_CHECK(TANKER_VERIFICATION_METHOD_PREVERIFIED_PHONE_NUMBER, Verification::Method::PreverifiedPhoneNumber);
STATIC_ENUM_CHECK(TANKER_VERIFICATION_METHOD_PREVERIFIED_OIDC, Verification::Method::PreverifiedOidc);
STATIC_ENUM_CHECK(TANKER_VERIFICATION_METHOD_OIDC_AUTHORIZATION_CODE, Verification::Method::OidcAuthorizationCode);
STATIC_ENUM_CHECK(TANKER_VERIFICATION_METHOD_PREHASHED_AND_ENCRYPTED_PASSPHRASE, Verification::Method::PrehashedAndEncryptedPassphrase);
STATIC_ENUM_CHECK(TANKER_VERIFICATION_METHOD_LAST, Verification::Method::Last);

static_assert(TANKER_VERIFICATION_METHOD_LAST == 12,
              "Please update the assertions above if you added a new "
              "unlock method");

// Status

STATIC_ENUM_CHECK(TANKER_STATUS_STOPPED, Status::Stopped);
STATIC_ENUM_CHECK(TANKER_STATUS_READY, Status::Ready);
STATIC_ENUM_CHECK(TANKER_STATUS_IDENTITY_REGISTRATION_NEEDED, Status::IdentityRegistrationNeeded);
STATIC_ENUM_CHECK(TANKER_STATUS_IDENTITY_VERIFICATION_NEEDED, Status::IdentityVerificationNeeded);

STATIC_ENUM_CHECK(TANKER_STATUS_LAST, Status::Last);

static_assert(TANKER_STATUS_LAST == 4, "Please update the status assertions above if you added a new status");

#undef STATIC_ENUM_CHECK

std::unique_ptr<Tanker::Network::Backend> extractNetworkBackend(tanker_http_options_t const& options)
{
  auto const httpHandlersCount = !!options.send_request + !!options.cancel_request;
  if (httpHandlersCount != 0 && httpHandlersCount != 2)
    throw Exception(make_error_code(Errc::InternalError), "the provided HTTP implementation is incomplete");
  if (httpHandlersCount == 0)
    return nullptr;
  return std::make_unique<CTankerBackend>(options);
}
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
      throw Exception(make_error_code(Errc::InvalidArgument), "options is null");
    }
    if (options->version != 4)
    {
      throw Exception(make_error_code(Errc::InvalidArgument),
                      fmt::format("options version should be {:d} instead of {:d}", 4, options->version));
    }
    if (options->app_id == nullptr)
    {
      throw Exception(make_error_code(Errc::InvalidArgument), "app_id is null");
    }
    if (options->sdk_type == nullptr)
    {
      throw Exception(make_error_code(Errc::InvalidArgument), "sdk_type is null");
    }
    if (options->sdk_version == nullptr)
    {
      throw Exception(make_error_code(Errc::InvalidArgument), "sdk_version is null");
    }

    char const* url = options->url;
    if (url == nullptr)
      url = "https://api.tanker.io";

    if (options->persistent_path == nullptr)
    {
      throw Exception(make_error_code(Errc::InvalidArgument), "persistent_path is null");
    }

    std::unique_ptr<Tanker::Network::Backend> networkBackend = extractNetworkBackend(options->http_options);
    std::unique_ptr<Tanker::DataStore::Backend> storageBackend = extractStorageBackend(options->datastore_options);

    if (options->cache_path == nullptr)
    {
      throw Exception(make_error_code(Errc::InvalidArgument), "cache_path is null");
    }

    try
    {
      auto const trustchainId = mgs::base64::decode<Trustchain::TrustchainId>(std::string(options->app_id));

      return static_cast<void*>(new AsyncCore(url,
                                              {options->sdk_type, trustchainId, options->sdk_version},
                                              options->persistent_path,
                                              options->cache_path,
                                              std::move(networkBackend),
                                              std::move(storageBackend)));
    }
    catch (mgs::exceptions::exception const&)
    {
      throw Exception(make_error_code(Errc::InvalidArgument), "app_id is invalid");
    }
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
      return tanker->connectSessionClosed([=, cb = std::move(cb)] { cb(nullptr, data); });
    default:
      throw formatEx(Errc::InvalidArgument, FMT_STRING("unknown event: {:d}"), static_cast<int>(event));
    }
  }));
}

tanker_expected_t* tanker_event_disconnect(tanker_t* ctanker, enum tanker_event event)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tc::sync([&] {
    switch (event)
    {
    case TANKER_EVENT_SESSION_CLOSED:
      tanker->disconnectSessionClosed();
      break;
    default:
      throw formatEx(Errc::InvalidArgument, FMT_STRING("unknown event: {:d}"), static_cast<int>(event));
    }
  }));
}

tanker_future_t* tanker_start(tanker_t* ctanker, char const* identity)
{
  if (identity == nullptr)
    return makeFuture(
        tc::make_exceptional_future<void>(Exception(make_error_code(Errc::InvalidArgument), "identity is null")));

  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->start(identity).and_then(tc::get_synchronous_executor(),
                                                     [](auto status) { return reinterpret_cast<void*>(status); }));
}

tanker_expected_t* tanker_enroll_user(tanker_t* ctanker,
                                      char const* identity,
                                      tanker_verification_list_t const* cverifications)
{
  if (identity == nullptr)
    return makeFuture(
        tc::make_exceptional_future<void>(Exception(make_error_code(Errc::InvalidArgument), "identity is null")));

  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tc::sync([&] {
                      auto const verifications = cverificationListToVerifications(cverifications);
                      return tanker->enrollUser(identity, verifications);
                    }).unwrap());
}

tanker_future_t* tanker_register_identity(tanker_t* ctanker,
                                          tanker_verification_t const* cverification,
                                          tanker_verification_options_t const* cverif_opts)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tc::sync([&] {
                      auto withToken = withTokenFromVerifOptions(cverif_opts);
                      auto const verification = cverificationToVerification(cverification);
                      return tanker->registerIdentity(verification, withToken);
                    })
                        .unwrap()
                        .and_then(tc::get_synchronous_executor(), [](auto const& token) {
                          if (!token.has_value())
                            return static_cast<void*>(nullptr);
                          return static_cast<void*>(duplicateString(*token));
                        }));
}

tanker_future_t* tanker_verify_identity(tanker_t* ctanker,
                                        tanker_verification_t const* cverification,
                                        tanker_verification_options_t const* cverif_opts)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tc::sync([&] {
                      auto withToken = withTokenFromVerifOptions(cverif_opts);
                      auto const verification = cverificationToVerification(cverification);
                      return tanker->verifyIdentity(verification, withToken);
                    })
                        .unwrap()
                        .and_then(tc::get_synchronous_executor(), [](auto const& token) {
                          if (!token.has_value())
                            return static_cast<void*>(nullptr);
                          return static_cast<void*>(duplicateString(*token));
                        }));
}

tanker_future_t* tanker_stop(tanker_t* ctanker)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->stop());
}

tanker_future_t* tanker_create_oidc_nonce(tanker_t* ctanker)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->createOidcNonce().and_then(tc::get_synchronous_executor(), [](auto const& oidcNonce) {
    return static_cast<void*>(duplicateString(oidcNonce.string()));
  }));
}

tanker_future_t* tanker_set_oidc_test_nonce(tanker_t* ctanker, char const* nonce)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->setOidcTestNonce(nonce));
}

enum tanker_status tanker_status(tanker_t* ctanker)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return static_cast<enum tanker_status>(tanker->status());
}

tanker_future_t* tanker_generate_verification_key(tanker_t* ctanker)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->generateVerificationKey().and_then(
      tc::get_synchronous_executor(), [](auto uk) { return static_cast<void*>(duplicateString(uk.string())); }));
}

tanker_future_t* tanker_set_verification_method(tanker_t* ctanker,
                                                tanker_verification_t const* cverification,
                                                tanker_verification_options_t const* cverif_opts)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tc::sync([&] {
                      auto withToken = withTokenFromVerifOptions(cverif_opts);
                      auto allowE2eMethodSwitch = allowE2eMethodSwitchFromVerifOptions(cverif_opts);
                      auto const verification = cverificationToVerification(cverification);
                      return tanker->setVerificationMethod(verification, withToken, allowE2eMethodSwitch);
                    })
                        .unwrap()
                        .and_then(tc::get_synchronous_executor(), [](auto const& token) {
                          if (!token.has_value())
                            return static_cast<void*>(nullptr);
                          return static_cast<void*>(duplicateString(*token));
                        }));
}

tanker_future_t* tanker_get_verification_methods(tanker_t* ctanker)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->getVerificationMethods().and_then(
      tc::get_synchronous_executor(), [](std::vector<Verification::VerificationMethod> methods) {
        auto verifMethods = new tanker_verification_method_t[methods.size()];
        for (size_t i = 0; i < methods.size(); ++i)
        {
          cVerificationMethodFromVerificationMethod(verifMethods[i], methods[i]);
        }
        auto verifMethodList = new tanker_verification_method_list;
        verifMethodList->count = methods.size();
        verifMethodList->methods = verifMethods;
        return reinterpret_cast<void*>(verifMethodList);
      }));
}

uint64_t tanker_encrypted_size(uint64_t clear_size, uint32_t padding_step)
{
  auto const paddingStepOpt = cPaddingToOptPadding(padding_step);
  return AsyncCore::encryptedSize(clear_size, paddingStepOpt);
}

tanker_expected_t* tanker_decrypted_size(uint8_t const* encrypted_data, uint64_t encrypted_size)
{
  return makeFuture(
      AsyncCore::decryptedSize(gsl::make_span(encrypted_data, encrypted_size))
          .and_then(tc::get_synchronous_executor(), [](auto size) { return reinterpret_cast<void*>(size); }));
}

tanker_expected_t* tanker_get_resource_id(uint8_t const* encrypted_data, uint64_t encrypted_size)
{
  return makeFuture(
      AsyncCore::getResourceId(gsl::make_span(static_cast<uint8_t const*>(encrypted_data), encrypted_size))
          .and_then(tc::get_synchronous_executor(),
                    [](auto resId) { return static_cast<void*>(duplicateString(resId.string())); }));
}

tanker_future_t* tanker_encrypt(tanker_t* ctanker,
                                uint8_t* encrypted_data,
                                uint8_t const* data,
                                uint64_t data_size,
                                tanker_encrypt_options_t const* options)
{
  return makeFuture(
      tc::sync([&] {
        std::vector<SPublicIdentity> spublicIdentities{};
        std::vector<SGroupId> sgroupIds{};
        bool shareWithSelf = true;
        std::optional<uint32_t> paddingStepOpt;
        if (options)
        {
          if (options->version != 4)
          {
            throw formatEx(Errc::InvalidArgument, "unsupported tanker_encrypt_options struct version");
          }
          spublicIdentities =
              to_vector<SPublicIdentity>(options->share_with_users, options->nb_users, "share_with_users");
          sgroupIds = to_vector<SGroupId>(options->share_with_groups, options->nb_groups, "share_with_groups");
          shareWithSelf = options->share_with_self;

          paddingStepOpt = cPaddingToOptPadding(options->padding_step);
        }

        auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
        return tanker->encrypt(gsl::span(encrypted_data, AsyncCore::encryptedSize(data_size, paddingStepOpt)),
                               gsl::make_span(data, data_size),
                               spublicIdentities,
                               sgroupIds,
                               Core::ShareWithSelf{shareWithSelf},
                               paddingStepOpt);
      }).unwrap());
}

tanker_future_t* tanker_decrypt(tanker_t* ctanker, uint8_t* decrypted_data, uint8_t const* data, uint64_t data_size)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(
      tc::sync([&] {
        auto encryptedSpan = gsl::make_span(data, data_size);
        auto decryptedSpan = gsl::make_span(decrypted_data, AsyncCore::decryptedSize(encryptedSpan).get());
        return tanker->decrypt(decryptedSpan, encryptedSpan);
      })
          .unwrap()
          .and_then(tc::get_synchronous_executor(), [](auto clearSize) { return reinterpret_cast<void*>(clearSize); }));
}

tanker_future_t* tanker_share(tanker_t* ctanker,
                              char const* const* resource_ids,
                              uint64_t nb_resource_ids,
                              tanker_sharing_options_t const* options)
{
  return makeFuture(tc::sync([&] {
                      if (!options)
                      {
                        throw formatEx(Errc::InvalidArgument, "tanker_sharing_options must not be NULL");
                      }

                      if (options->version != 1)
                      {
                        throw formatEx(Errc::InvalidArgument, "unsupported tanker_sharing_options struct version");
                      }

                      auto const spublicIdentities =
                          to_vector<SPublicIdentity>(options->share_with_users, options->nb_users, "share_with_users");
                      auto const sgroupIds =
                          to_vector<SGroupId>(options->share_with_groups, options->nb_groups, "share_with_groups");
                      auto const resources = to_vector<SResourceId>(resource_ids, nb_resource_ids, "resource_ids");
                      auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);

                      return tanker->share(resources, spublicIdentities, sgroupIds);
                    }).unwrap());
}

tanker_future_t* tanker_attach_provisional_identity(tanker_t* ctanker, char const* provisional_identity)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->attachProvisionalIdentity(SSecretProvisionalIdentity{provisional_identity})
                        .and_then(tc::get_synchronous_executor(), [](AttachResult const& attachResult) {
                          auto cAttachResult = new tanker_attach_result_t;
                          cAttachResult->version = 1;
                          cAttachResult->method = nullptr;
                          cAttachResult->status = static_cast<uint8_t>(attachResult.status);
                          if (attachResult.verificationMethod.has_value())
                          {
                            tanker_verification_method cMethod;
                            cVerificationMethodFromVerificationMethod(cMethod, *attachResult.verificationMethod);
                            cAttachResult->method = new tanker_verification_method(cMethod);
                          }
                          return reinterpret_cast<void*>(cAttachResult);
                        }));
}

tanker_future_t* tanker_verify_provisional_identity(tanker_t* ctanker, tanker_verification_t const* cverification)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tc::sync([&] {
                      auto const verification = cverificationToVerification(cverification);
                      return tanker->verifyProvisionalIdentity(verification);
                    }).unwrap());
}

tanker_expected_t* tanker_authenticate_with_idp(tanker_t* ctanker, char const* provider_id, char const* cookie)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->authenticateWithIdp(provider_id, cookie)
                        .and_then(tc::get_synchronous_executor(), [](OidcAuthorizationCode const& verification) {
                          auto cVerification = new tanker_oidc_authorization_code_verification_t;
                          cVerification->version = 1;
                          cVerification->provider_id = duplicateString(verification.provider_id);
                          cVerification->authorization_code = duplicateString(verification.authorization_code);
                          cVerification->state = duplicateString(verification.state);
                          return reinterpret_cast<void*>(cVerification);
                        }));
}

void tanker_free_buffer(void const* buffer)
{
  free(const_cast<void*>(buffer));
}

void tanker_free_verification_method_list(tanker_verification_method_list_t* methodList)
{
  for (size_t i = 0; i < methodList->count; ++i)
  {
    auto method_type = methodList->methods[i].verification_method_type;
    if (method_type == TANKER_VERIFICATION_METHOD_EMAIL || method_type == TANKER_VERIFICATION_METHOD_PHONE_NUMBER ||
        method_type == TANKER_VERIFICATION_METHOD_OIDC_ID_TOKEN)
      free(const_cast<char*>(methodList->methods[i].value1));
    if (method_type == TANKER_VERIFICATION_METHOD_OIDC_ID_TOKEN)
      free(const_cast<char*>(methodList->methods[i].value2));
  }
  delete[] methodList->methods;
  delete methodList;
}

void tanker_free_attach_result(tanker_attach_result_t* result)
{
  if (result->method)
  {
    auto method_type = result->method->verification_method_type;
    if (method_type == TANKER_VERIFICATION_METHOD_EMAIL || method_type == TANKER_VERIFICATION_METHOD_PHONE_NUMBER ||
        method_type == TANKER_VERIFICATION_METHOD_OIDC_ID_TOKEN)
      free(const_cast<char*>(result->method->value1));
    if (method_type == TANKER_VERIFICATION_METHOD_OIDC_ID_TOKEN)
      free(const_cast<char*>(result->method->value2));
    delete result->method;
  }
  delete result;
}

void tanker_free_authenticate_with_idp_result(tanker_oidc_authorization_code_verification_t* result)
{
  free(const_cast<char*>(result->provider_id));
  free(const_cast<char*>(result->authorization_code));
  free(const_cast<char*>(result->state));
  delete result;
}

tanker_expected_t* tanker_prehash_password(char const* password)
{
  return makeFuture(tc::sync([&] {
    if (!password)
      throw formatEx(Errc::InvalidArgument, "password is null");
    return static_cast<void*>(duplicateString(mgs::base64::encode(Crypto::prehashPassword(password))));
  }));
}

tanker_expected_t* tanker_prehash_and_encrypt_password(char const* password, char const* public_key)
{
  return makeFuture(tc::sync([&] {
    if (!password)
      throw formatEx(Errc::InvalidArgument, "password is null");
    if (!public_key)
      throw formatEx(Errc::InvalidArgument, "public_key is null");
    auto const decodedPublicKey =
        decodeArgument<mgs::base64, Crypto::PublicEncryptionKey>(std::string(public_key), "public_key");
    return static_cast<void*>(
        duplicateString(mgs::base64::encode(Crypto::prehashAndEncryptPassword(password, decodedPublicKey))));
  }));
}

void tanker_before_fork()
{
  tc::get_default_executor().stop_before_fork();
}

void tanker_after_fork()
{
  tc::get_default_executor().resume_after_fork();
}
