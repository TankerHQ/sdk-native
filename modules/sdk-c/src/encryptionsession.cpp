#include <ctanker/encryptionsession.h>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Streams/EncryptionStreamV4.hpp>

#include <ctanker/async/private/CFuture.hpp>
#include <ctanker/private/Utils.hpp>

#include "Stream.hpp"

using namespace Tanker;
using namespace Tanker::Errors;

CTANKER_EXPORT tanker_future_t* tanker_encryption_session_open(
    tanker_t* ctanker, tanker_encrypt_options_t const* options)
{
  return makeFuture(
      tc::sync([&] {
        std::vector<SPublicIdentity> spublicIdentities;
        std::vector<SGroupId> sgroupIds;
        bool shareWithSelf = true;
        if (options)
        {
          if (options->version != 3)
          {
            throw formatEx(Errc::InvalidArgument,
                           "unsupported tanker_encrypt_options struct version");
          }
          spublicIdentities = to_vector<SPublicIdentity>(
              options->share_with_users, options->nb_users, "share_with_users");
          sgroupIds = to_vector<SGroupId>(options->share_with_groups,
                                          options->nb_groups,
                                          "share_with_groups");
          shareWithSelf = options->share_with_self;
        }

        auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
        return tanker->makeEncryptionSession(
            spublicIdentities,
            sgroupIds,
            static_cast<Core::ShareWithSelf>(shareWithSelf));
      })
          .unwrap()
          .and_then(tc::get_synchronous_executor(), [](auto sess) {
            auto sessPtr = new EncryptionSession(std::move(sess));
            return reinterpret_cast<void*>(sessPtr);
          }));
}

CTANKER_EXPORT tanker_future_t* tanker_encryption_session_close(
    tanker_encryption_session_t* csession)
{
  auto const session = reinterpret_cast<EncryptionSession*>(csession);
  return makeFuture(tc::async([=] { delete session; }));
}

CTANKER_EXPORT uint64_t
tanker_encryption_session_encrypted_size(uint64_t clearSize)
{
  return EncryptionSession::encryptedSize(clearSize);
}

CTANKER_EXPORT tanker_expected_t* tanker_encryption_session_get_resource_id(
    tanker_encryption_session_t* csession)
{
  auto const session = reinterpret_cast<EncryptionSession*>(csession);
  auto resourceId = mgs::base64::encode<SResourceId>(session->resourceId());
  return makeFuture(tc::make_ready_future(
      static_cast<void*>(duplicateString(resourceId.string()))));
}

CTANKER_EXPORT tanker_future_t* tanker_encryption_session_encrypt(
    tanker_encryption_session_t* csession,
    uint8_t* encrypted_data,
    uint8_t const* data,
    uint64_t data_size)
{
  auto session = reinterpret_cast<EncryptionSession*>(csession);
  return makeFuture(session->canceler()->run([&]() mutable {
    return tc::async_resumable([=]() -> tc::cotask<void> {
      auto const encryptedSpan =
          gsl::make_span(encrypted_data, session->encryptedSize(data_size));
      TC_AWAIT(
          session->encrypt(encryptedSpan, gsl::make_span(data, data_size)));
    });
  }));
}

tanker_future_t* tanker_encryption_session_stream_encrypt(
    tanker_encryption_session_t* csession,
    tanker_stream_input_source_t cb,
    void* additional_data)
{
  auto session = reinterpret_cast<EncryptionSession*>(csession);
  return makeFuture(tc::sync([&] {
    auto wrappedCb = wrapCallback(cb, additional_data);
    auto [encryptor, resourceId] =
        session->makeEncryptionStream(std::move(wrappedCb));

    auto c_stream = new tanker_stream;
    c_stream->resourceId = SResourceId{mgs::base64::encode(resourceId)};
    c_stream->inputSource = std::move(encryptor);
    return static_cast<void*>(c_stream);
  }));
}
