#include <ctanker.h>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Unlock/Methods.hpp>
#include <Tanker/Init.hpp>

#include <tconcurrent/async.hpp>
#include <tconcurrent/thread_pool.hpp>

#include "CFuture.hpp"
#include "Utils.hpp"

#include <string>
#include <utility>

using namespace Tanker;

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

#define UNLOCK_ENUM_CHECK(cval, cppval) \
  static_assert(cval == static_cast<int>(cppval), "UNLOCK enums not in sync")

UNLOCK_ENUM_CHECK(TANKER_UNLOCK_METHOD_EMAIL, Unlock::Method::Email);
UNLOCK_ENUM_CHECK(TANKER_UNLOCK_METHOD_PASSWORD, Unlock::Method::Password);

UNLOCK_ENUM_CHECK(TANKER_UNLOCK_METHOD_LAST, Unlock::Method::Last);
#undef UNLOCK_ENUM_CHECK

static_assert(TANKER_UNLOCK_METHOD_LAST == 2,
              "Please update the event assertions above if you added a new "
              "unlock methods");
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
      throw Error::formatEx<Error::InvalidArgument>("options is null");
    if (options->version != 2)
      throw Error::formatEx<Error::InvalidArgument>(
          "options version is {:d} should be {:d}", options->version, 2);
    if (options->trustchain_id == nullptr)
      throw Error::formatEx<Error::InvalidArgument>("trustchain_id is null");
    if (options->sdk_type == nullptr)
      throw Error::formatEx<Error::InvalidArgument>("sdk_type is null");
    if (options->sdk_version == nullptr)
      throw Error::formatEx<Error::InvalidArgument>("sdk_version is null");

    char const* url = options->trustchain_url;
    if (url == nullptr)
      url = "https://api.tanker.io";

    if (options->writable_path == nullptr)
      throw Error::formatEx<Error::InvalidArgument>("writable_path is null");

    return static_cast<void*>(new AsyncCore(
        url,
        {options->sdk_type,
         base64::decode<TrustchainId>(std::string(options->trustchain_id)),
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
  AsyncCore::setLogHandler(handler);
}

tanker_expected_t* tanker_event_connect(tanker_t* ctanker,
                                        enum tanker_event event,
                                        tanker_event_callback_t cb,
                                        void* data)
{
#define EVENT_ENUM_CHECK(cval, cppval) \
  static_assert(cval == static_cast<int>(cppval), "Event enums not in sync")

  EVENT_ENUM_CHECK(TANKER_EVENT_SESSION_CLOSED, Event::SessionClosed);
  EVENT_ENUM_CHECK(TANKER_EVENT_DEVICE_CREATED, Event::DeviceCreated);
  EVENT_ENUM_CHECK(TANKER_EVENT_UNLOCK_REQUIRED, Event::UnlockRequired);
  EVENT_ENUM_CHECK(TANKER_EVENT_DEVICE_REVOKED, Event::DeviceRevoked);

#undef EVENT_ENUM_CHECK

  static_assert(
      TANKER_EVENT_LAST == 4,
      "Please update the event assertions above if you added a new event");

  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(
      tanker->connectEvent(static_cast<Event>(event), cb, data)
          .and_then(tc::get_synchronous_executor(), [](auto conn) {
            return reinterpret_cast<void*>(new auto(std::move(conn)));
          }));
}

tanker_expected_t* tanker_event_disconnect(tanker_t* ctanker,
                                           tanker_connection_t* cconnection)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->disconnectEvent(std::move(
      *reinterpret_cast<boost::signals2::scoped_connection*>(cconnection))));
}

tanker_future_t* tanker_open(tanker_t* ctanker,
                             char const* user_id,
                             char const* user_token)
{
  if (user_id == nullptr)
    return makeFuture(tc::make_exceptional_future<void>(
        Error::formatEx<Error::InvalidArgument>("user_id is null")));
  if (user_token == nullptr)
    return makeFuture(tc::make_exceptional_future<void>(
        Error::formatEx<Error::InvalidArgument>("user_token is null")));

  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->open(SUserId(user_id), std::string(user_token)));
}

tanker_future_t* tanker_close(tanker_t* ctanker)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->close());
}

enum tanker_status tanker_get_status(tanker_t* ctanker)
{
#define STATIC_ENUM_CHECK(cval, cppval) \
  static_assert(cval == static_cast<int>(cppval), "Status enums not in sync")

  STATIC_ENUM_CHECK(TANKER_STATUS_CLOSED, Status::Closed);
  STATIC_ENUM_CHECK(TANKER_STATUS_USER_CREATION, Status::UserCreation);
  STATIC_ENUM_CHECK(TANKER_STATUS_DEVICE_CREATION, Status::DeviceCreation);
  STATIC_ENUM_CHECK(TANKER_STATUS_OPEN, Status::Open);

  STATIC_ENUM_CHECK(TANKER_STATUS_LAST, Status::Last);

#undef STATIC_ENUM_CHECK

  static_assert(
      TANKER_STATUS_LAST == 5,
      "Please update the status assertions above if you added a new status");

  return static_cast<tanker_status>(
      reinterpret_cast<AsyncCore*>(ctanker)->status());
}

tanker_future_t* tanker_device_id(tanker_t* ctanker)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  auto fut = tanker->deviceId().and_then(
      tc::get_synchronous_executor(), [](auto const& deviceId) {
        auto const encodedSize = tanker_base64_encoded_size(deviceId.size());
        auto const ret = static_cast<b64char*>(std::malloc(encodedSize + 1));
        if (!ret)
          throw std::bad_alloc{};
        tanker_base64_encode(ret, deviceId.data(), deviceId.size());
        ret[encodedSize] = '\0';
        return reinterpret_cast<void*>(ret);
      });
  return makeFuture(std::move(fut));
}

tanker_future_t* tanker_generate_and_register_unlock_key(tanker_t* ctanker)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->generateAndRegisterUnlockKey().and_then(
      tc::get_synchronous_executor(), [](auto uk) {
        return static_cast<void*>(duplicateString(uk.string()));
      }));
}

tanker_future_t* tanker_setup_unlock(tanker_t* ctanker,
                                     char const* email,
                                     char const* pass)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->setupUnlock(Unlock::CreationOptions{
      nullableToOpt<Email>(email), nullableToOpt<Password>(pass)}));
}

tanker_future_t* tanker_update_unlock(tanker_t* ctanker,
                                      char const* email,
                                      char const* pass,
                                      char const* unlockKey)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->updateUnlock(
      Unlock::UpdateOptions{nullableToOpt<Email>(email),
                            nullableToOpt<Password>(pass),
                            nullableToOpt<UnlockKey>(unlockKey)}));
}

tanker_future_t* tanker_register_unlock(tanker_t* ctanker,
                                        char const* new_email,
                                        char const* new_password)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->registerUnlock(Unlock::CreationOptions{
      nullableToOpt<Email>(new_email), nullableToOpt<Password>(new_password)}));
}

tanker_future_t* tanker_unlock_current_device_with_password(tanker_t* ctanker,
                                                            char const* pass)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->unlockCurrentDevice(Password{pass}));
}

tanker_future_t* tanker_unlock_current_device_with_verification_code(
    tanker_t* ctanker, char const* code)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->unlockCurrentDevice(VerificationCode{code}));
}

tanker_future_t* tanker_unlock_current_device_with_unlock_key(
    tanker_t* ctanker, char const* unlockKey)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->unlockCurrentDevice(UnlockKey{unlockKey}));
}

tanker_future_t* tanker_is_unlock_already_set_up(tanker_t* ctanker)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->isUnlockAlreadySetUp().and_then(
      tc::get_synchronous_executor(),
      [](bool value) { return reinterpret_cast<void*>(value); }));
}

tanker_expected_t* tanker_registered_unlock_methods(tanker_t* ctanker)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->registeredUnlockMethods().and_then(
      tc::get_synchronous_executor(), [](Unlock::Methods m) {
        return reinterpret_cast<void*>(m.underlying_value());
      }));
}

tanker_expected_t* tanker_has_registered_unlock_methods(tanker_t* ctanker)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->hasRegisteredUnlockMethods().and_then(
      tc::get_synchronous_executor(),
      [](bool b) { return reinterpret_cast<void*>(b); }));
}

tanker_expected_t* tanker_has_registered_unlock_method(
    tanker_t* ctanker, enum tanker_unlock_method method)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(
      tanker->hasRegisteredUnlockMethods(static_cast<Unlock::Method>(method))
          .and_then(tc::get_synchronous_executor(),
                    [](bool b) { return reinterpret_cast<void*>(b); }));
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
  std::vector<SUserId> suserIds{};
  std::vector<SGroupId> sgroupIds{};
  if (options)
  {
    suserIds =
        to_vector<SUserId>(options->recipient_uids, options->nb_recipient_uids);
    sgroupIds = to_vector<SGroupId>(options->recipient_gids,
                                    options->nb_recipient_gids);
  }
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(tanker->encrypt(
      encrypted_data, gsl::make_span(data, data_size), suserIds, sgroupIds));
}

tanker_future_t* tanker_decrypt(tanker_t* ctanker,
                                uint8_t* decrypted_data,
                                uint8_t const* data,
                                uint64_t data_size,
                                tanker_decrypt_options_t const* options)
{
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  return makeFuture(
      tanker->decrypt(decrypted_data, gsl::make_span(data, data_size)));
}

tanker_future_t* tanker_share(tanker_t* ctanker,
                              char const* const* recipient_uids,
                              uint64_t nb_recipient_uids,
                              char const* const* recipient_gids,
                              uint64_t nb_recipient_gids,
                              b64char const* const* resource_ids,
                              uint64_t nb_resource_ids) try
{
  auto suserIds = to_vector<SUserId>(recipient_uids, nb_recipient_uids);
  auto sgroupIds = to_vector<SGroupId>(recipient_gids, nb_recipient_gids);
  auto resources = to_vector<SResourceId>(resource_ids, nb_resource_ids);
  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);

  return makeFuture(tanker->share(resources, suserIds, sgroupIds));
}
catch (std::exception const& e)
{
  return makeFuture(tc::make_exceptional_future<void>(e));
}

tanker_future_t* tanker_revoke_device(tanker_t* ctanker,
                                      b64char const* device_id)
{
  auto const tanker = reinterpret_cast<AsyncCore*>(ctanker);
  auto const device_id_size = std::strlen(device_id);
  auto const deviceId =
      base64::decode<DeviceId>(gsl::make_span(device_id, device_id_size));
  return makeFuture(tanker->revokeDevice(deviceId));
}

void tanker_free_buffer(void* buffer)
{
  free(buffer);
}
