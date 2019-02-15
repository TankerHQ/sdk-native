#include <tanker.h>

#include <string>
#include <utility>

#include <Tanker/AsyncCore.hpp>
#include <Tanker/ChunkEncryptor.hpp>
#include <Tanker/Crypto/Types.hpp>
#include <Tanker/Error.hpp>
#include <Tanker/Log.hpp>
#include <Tanker/LogHandler.hpp>

#include "CFuture.hpp"
#include "Utils.hpp"

using namespace Tanker;

tanker_future_t* tanker_make_chunk_encryptor(tanker_t* session)
{
  auto tanker = reinterpret_cast<AsyncCore*>(session);
  return makeFuture(tanker->makeChunkEncryptor().and_then(
      tc::get_synchronous_executor(),
      [](auto chunky) { return static_cast<void*>(chunky.release()); }));
}

tanker_future_t* tanker_make_chunk_encryptor_from_seal(
    tanker_t* session,
    uint8_t const* data,
    uint64_t data_size,
    tanker_decrypt_options_t const* options)
{
  auto tanker = reinterpret_cast<AsyncCore*>(session);
  return makeFuture(
      tanker->makeChunkEncryptor(gsl::make_span(data, data_size))
          .and_then(tc::get_synchronous_executor(), [](auto chunky) {
            return static_cast<void*>(chunky.release());
          }));
}

uint64_t tanker_chunk_encryptor_seal_size(
    tanker_chunk_encryptor_t* chunk_encryptor)
{
  auto const chunkEncryptor =
      reinterpret_cast<ChunkEncryptor*>(chunk_encryptor);
  return chunkEncryptor->sealSize();
}

tanker_future_t* tanker_chunk_encryptor_seal(
    tanker_chunk_encryptor_t* chunk_encryptor,
    uint8_t* encrypted_seal,
    tanker_encrypt_options_t const* options)
{
  auto userIds = std::vector<SUserId>{};
  auto groupIds = std::vector<SGroupId>{};
  if (options)
  {
    userIds =
        to_vector<SUserId>(options->recipient_uids, options->nb_recipient_uids);
    groupIds = to_vector<SGroupId>(options->recipient_gids,
                                   options->nb_recipient_gids);
  }

  return makeFuture(tc::async_resumable(
      [chunkEncryptor = reinterpret_cast<ChunkEncryptor*>(chunk_encryptor),
       encrypted_seal,
       userIds = std::move(userIds),
       groupIds = std::move(groupIds)]() -> tc::cotask<void> {
        TC_AWAIT(chunkEncryptor->seal(
            gsl::make_span(encrypted_seal, chunkEncryptor->sealSize()),
            userIds,
            groupIds));
      }));
}

uint64_t tanker_chunk_encryptor_chunk_count(
    tanker_chunk_encryptor_t* chunk_encryptor)
{
  auto const chunkEncryptor =
      reinterpret_cast<ChunkEncryptor*>(chunk_encryptor);
  return chunkEncryptor->size();
}

tanker_future_t* tanker_chunk_encryptor_encrypt_append(
    tanker_chunk_encryptor_t* chunk_encryptor,
    uint8_t* encrypted_data,
    uint8_t const* data,
    uint64_t data_size)
{
  return makeFuture(tc::sync(
      [chunkEncryptor = reinterpret_cast<ChunkEncryptor*>(chunk_encryptor),
       encryptedData = gsl::make_span(encrypted_data,
                                      ChunkEncryptor::encryptedSize(data_size)),
       data = gsl::make_span(data, data_size)]() {
        chunkEncryptor->encrypt(encryptedData, data);
      }));
}

tanker_future_t* tanker_chunk_encryptor_encrypt_at(
    tanker_chunk_encryptor_t* chunk_encryptor,
    uint8_t* encrypted_data,
    uint8_t const* data,
    uint64_t data_size,
    uint64_t index)
{
  return makeFuture(tc::sync(
      [chunkEncryptor = reinterpret_cast<ChunkEncryptor*>(chunk_encryptor),
       index,
       encryptedData = gsl::make_span(encrypted_data,
                                      ChunkEncryptor::encryptedSize(data_size)),
       data = gsl::make_span(data, data_size)]() {
        chunkEncryptor->encrypt(encryptedData, data, index);
      }));
}

tanker_future_t* tanker_chunk_encryptor_decrypt(
    tanker_chunk_encryptor_t* chunk_encryptor,
    uint8_t* decrypted_data,
    uint8_t const* encrypted_data,
    uint64_t encrypted_data_size,
    uint64_t index)
{
  auto encryptedData = gsl::make_span(encrypted_data, encrypted_data_size);

  return makeFuture(tc::sync(
      [chunkEncryptor = reinterpret_cast<ChunkEncryptor*>(chunk_encryptor),
       index,
       decryptedData = gsl::make_span(
           decrypted_data, ChunkEncryptor::decryptedSize(encryptedData)),
       encryptedData = std::move(encryptedData)]() {
        chunkEncryptor->decrypt(decryptedData, encryptedData, index);
      }));
}

uint64_t tanker_chunk_encryptor_encrypted_size(uint64_t clear_size)
{
  return ChunkEncryptor::encryptedSize(clear_size);
}

tanker_expected_t* tanker_chunk_encryptor_decrypted_size(
    uint8_t const* encrypted_data, uint64_t encrypted_size)
{
  return makeFuture(tc::sync([&] {
    return reinterpret_cast<void*>(ChunkEncryptor::decryptedSize(
        gsl::make_span(encrypted_data, encrypted_size)));
  }));
}

tanker_future_t* tanker_chunk_encryptor_remove(
    tanker_chunk_encryptor_t* chunk_encryptor,
    uint64_t const* indexes,
    uint64_t indexes_size)
{
  return makeFuture(tc::sync(
      [chunkEncryptor = reinterpret_cast<ChunkEncryptor*>(chunk_encryptor),
       indexes_list = gsl::make_span(indexes, indexes_size)]() {
        chunkEncryptor->remove(indexes_list);
      }));
}

tanker_expected_t* tanker_chunk_encryptor_destroy(
    tanker_chunk_encryptor_t* chunk_encryptor)
{
  if (tc::get_default_executor().is_in_this_context())
    return makeFuture(tc::sync(
        [&]() { delete reinterpret_cast<ChunkEncryptor*>(chunk_encryptor); }));
  else
    return makeFuture(tc::async([chunk = reinterpret_cast<ChunkEncryptor*>(
                                     chunk_encryptor)]() { delete chunk; }));
}
