#include <ctanker/encryptionsession.h>

#include <Tanker/AsyncCore.hpp>

#include "Stream.hpp"
#include <ctanker/async/private/CFuture.hpp>
#include <ctanker/private/Utils.hpp>

using namespace Tanker;
using namespace Tanker::Errors;

CTANKER_EXPORT tanker_future_t* tanker_encryption_session_open(
    tanker_t* ctanker, tanker_encrypt_options_t const* options)
{
  std::vector<SPublicIdentity> spublicIdentities;
  std::vector<SGroupId> sgroupIds;
  bool shareWithSelf = true;
  if (options)
  {
    if (options->version != 3)
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
    shareWithSelf = options->share_with_self;
  }

  auto tanker = reinterpret_cast<AsyncCore*>(ctanker);
  auto sessFuture = tanker->makeEncryptionSession(
      spublicIdentities,
      sgroupIds,
      shareWithSelf ? Core::ShareWithSelf::Yes : Core::ShareWithSelf::No);
  return makeFuture(
      sessFuture.and_then(tc::get_synchronous_executor(), [](auto const& sess) {
        // Horribly unsafe, but we have no way std::move from a shared_future
        auto sessPtr = new EncryptionSession(sess);
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
  auto resourceId =
      mgs::base64::encode<SResourceId>(session->resourceId());
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
      TC_AWAIT(
          session->encrypt(encrypted_data, gsl::make_span(data, data_size)));
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
    auto resourceId = session->resourceId();
    auto key = session->sessionKey();
    auto wrappedCb = wrapCallback(cb, additional_data);
    Streams::EncryptionStream encryptor(std::move(wrappedCb), resourceId, key);

    auto c_stream = new tanker_stream;
    c_stream->resourceId =
        SResourceId{mgs::base64::encode(encryptor.resourceId())};
    c_stream->inputSource = std::move(encryptor);
    return static_cast<void*>(c_stream);
  }));
}
