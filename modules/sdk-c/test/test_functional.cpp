#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <doctest.h>
#include <sodium.h>

#include <tanker.h>
#include <tanker/user_token.h>

#include <Tanker/Crypto/base64.hpp>

#include "Helpers.hpp"
#include <Helpers/UniquePath.hpp>

#include <fmt/format.h>

namespace
{
std::string serverSideTokenGeneration(std::string const& userId,
                                      std::string const& trustchainId,
                                      std::string const& trustchainPrivateKey)
{
  tanker_expected_t* future_token = tanker_generate_user_token(
      trustchainId.c_str(), trustchainPrivateKey.c_str(), userId.c_str());
  char* token = (char*)tanker_future_get_voidptr(future_token);
  tanker_future_destroy(future_token);
  std::string const userToken(token);
  tanker_free_buffer(token);
  return userToken;
}

std::string generateRandomUserId()
{
  auto const storage_size = 8u;
  std::vector<uint8_t> storage(storage_size);
  randombytes_buf(storage.data(), storage_size);
  return Tanker::base64::encode(storage);
}

tanker_t* create_user(TestTrustchain const& trustchain)
{
  tanker_options_t opts = TANKER_OPTIONS_INIT;
  opts.trustchain_url = trustchain.url();
  opts.trustchain_id = trustchain.id();
  UniquePath prefix("tmptest");
  opts.writable_path = prefix.path.c_str();

  tanker_future_t* result = tanker_create(&opts);
  tanker_future_wait(result);
  tanker_t* tanker = (tanker_t*)tanker_future_get_voidptr(result);
  tanker_future_destroy(result);

  auto const userId = generateRandomUserId();
  auto const userToken = serverSideTokenGeneration(
      userId, trustchain.id(), trustchain.privateKey());

  tanker_future_t* future_open =
      tanker_open(tanker, userId.c_str(), userToken.c_str());
  tanker_future_wait(future_open);
  REQUIRE(tanker_future_has_error(future_open) == 0);
  tanker_future_destroy(future_open);

  return tanker;
}
}

TEST_CASE("getting the error of a tanker_future twice should not crash")
{
  tanker_future_t* result = tanker_create(nullptr);
  tanker_future_wait(result);
  CHECK(tanker_future_has_error(result));
  tanker_future_get_error(result);
  tanker_future_get_error(result);
}

TEST_CASE("decrypted_size should return an error if the buffer is too small")
{
  uint8_t const corruptedBuf[] = {2, 2, 3, 4};

  tanker_expected_t* result =
      tanker_decrypted_size(corruptedBuf, sizeof(corruptedBuf));

  tanker_error_t* error = tanker_future_get_error(result);
  REQUIRE(error);
  INFO(error->message);
  CHECK(error->code == TANKER_ERROR_DECRYPT_FAILED);

  tanker_future_destroy(result);
}

TEST_CASE("tanker_create should throw an error if the base64 is invalid")
{
  tanker_options_t opts = TANKER_OPTIONS_INIT;
  opts.trustchain_id = ",,,,!!";
  UniquePath prefix("tmptest");
  opts.writable_path = prefix.path.c_str();

  tanker_future_t* result = tanker_create(&opts);
  tanker_future_wait(result);

  tanker_error_t* error = tanker_future_get_error(result);
  REQUIRE(error);
  INFO(error->message);
  CHECK(error->code == TANKER_ERROR_INVALID_ARGUMENT);

  tanker_future_destroy(result);
}

TEST_CASE("Create/destroy tanker instance")
{
  TestTrustchain trustchain;

  tanker_options_t opts = TANKER_OPTIONS_INIT;
  opts.trustchain_id = trustchain.id();
  UniquePath prefix("tmptest");
  opts.writable_path = prefix.path.c_str();

  tanker_future_t* result = tanker_create(&opts);
  tanker_future_wait(result);

  REQUIRE(tanker_future_has_error(result) == 0);

  tanker_t* tanker = (tanker_t*)tanker_future_get_voidptr(result);
  tanker_future_t* future_destroy = tanker_destroy(tanker);
  tanker_future_wait(future_destroy);
  REQUIRE(tanker_future_has_error(future_destroy) == 0);

  tanker_future_destroy(result);
  tanker_future_destroy(future_destroy);
}

TEST_CASE("Connect/Disconnect tanker instance")
{
  TestTrustchain trustchain;

  tanker_options_t opts = TANKER_OPTIONS_INIT;
  opts.trustchain_url = trustchain.url();
  opts.trustchain_id = trustchain.id();
  UniquePath prefix("tmptest");
  opts.writable_path = prefix.path.c_str();

  tanker_future_t* result = tanker_create(&opts);
  tanker_future_wait(result);
  tanker_t* tanker = (tanker_t*)tanker_future_get_voidptr(result);
  tanker_future_destroy(result);

  tanker_future_t* future_connect =
      tanker_event_connect(tanker, TANKER_EVENT_UNLOCK_REQUIRED, NULL, NULL);
  tanker_future_wait(future_connect);

  REQUIRE(tanker_future_has_error(future_connect) == 0);

  tanker_connection_t* unlock_required_connection =
      (tanker_connection_t*)tanker_future_get_voidptr(future_connect);
  tanker_future_destroy(future_connect);

  SUBCASE("Disconnect first then destroy")
  {
    tanker_future_t* future_disconnect =
        tanker_event_disconnect(tanker, unlock_required_connection);
    tanker_future_wait(future_disconnect);
    REQUIRE(tanker_future_has_error(future_disconnect) == 0);
    tanker_future_destroy(future_disconnect);

    tanker_future_t* future_destroy = tanker_destroy(tanker);
    tanker_future_wait(future_destroy);
    REQUIRE(tanker_future_has_error(future_destroy) == 0);
    tanker_future_destroy(future_destroy);
  }

  SUBCASE("Destroy first then disconnect")
  {
    tanker_future_t* future_destroy = tanker_destroy(tanker);
    tanker_future_wait(future_destroy);
    REQUIRE(tanker_future_has_error(future_destroy) == 0);
    tanker_future_destroy(future_destroy);

    tanker_future_t* future_disconnect =
        tanker_event_disconnect(tanker, unlock_required_connection);
    tanker_future_wait(future_disconnect);
    REQUIRE(tanker_future_has_error(future_disconnect) == 0);
    tanker_future_destroy(future_disconnect);
  }
}

TEST_CASE("Open tanker instance")
{
  TestTrustchain trustchain;

  auto tanker = create_user(trustchain);

  tanker_future_t* future_destroy = tanker_destroy(tanker);
  tanker_future_wait(future_destroy);
  tanker_future_destroy(future_destroy);
}

TEST_CASE("unlockKey")
{
  TestTrustchain trustchain;

  auto tanker = create_user(trustchain);

  SUBCASE("generate and register")
  {
    tanker_future_t* fut_unlock_key =
        tanker_generate_and_register_unlock_key(tanker);
    tanker_future_wait(fut_unlock_key);
    FAST_REQUIRE_UNARY_FALSE(tanker_future_has_error(fut_unlock_key));
    b64char* unlockKey = (b64char*)tanker_future_get_voidptr(fut_unlock_key);
    fmt::print("unlockKey is: '{}'\n", unlockKey);
    tanker_future_destroy(fut_unlock_key);
    tanker_free_buffer(unlockKey);
  }
  SUBCASE("upload and fetch unlock key")
  {
    tanker_future_t* fut_setup =
        tanker_setup_unlock(tanker, NULL, "my password");
    tanker_future_wait(fut_setup);
    FAST_REQUIRE_UNARY_FALSE(tanker_future_has_error(fut_setup));
  }
  SUBCASE("upload and update unlock key")
  {
    tanker_future_t* fut_setup =
        tanker_setup_unlock(tanker, NULL, "my password");
    tanker_future_wait(fut_setup);
    FAST_REQUIRE_UNARY_FALSE(tanker_future_has_error(fut_setup));
    tanker_future_t* fut_update =
        tanker_update_unlock(tanker, NULL, "my new password", NULL);
    tanker_future_wait(fut_update);
    FAST_REQUIRE_UNARY_FALSE(tanker_future_has_error(fut_update));
  }

  SUBCASE("test if unlock already set up")
  {
    {
      tanker_future_t* expect_setup1 = tanker_is_unlock_already_set_up(tanker);
      tanker_future_wait(expect_setup1);
      FAST_REQUIRE_UNARY_FALSE(tanker_future_has_error(expect_setup1));
      size_t isSetup1 = (size_t)tanker_future_get_voidptr(expect_setup1);
      FAST_REQUIRE_UNARY_FALSE(isSetup1);
    }
    {
      tanker_future_t* fut_setup =
          tanker_setup_unlock(tanker, NULL, "my password");
      tanker_future_wait(fut_setup);
      FAST_REQUIRE_UNARY_FALSE(tanker_future_has_error(fut_setup));
    }
    {
      sleep(1); // we wait for the ghostDevice to came back
      tanker_expected_t* expect_setup2 =
          tanker_is_unlock_already_set_up(tanker);
      tanker_future_wait(expect_setup2);
      FAST_REQUIRE_UNARY_FALSE(tanker_future_has_error(expect_setup2));
      size_t isSetup2 = (size_t)tanker_future_get_voidptr(expect_setup2);
      FAST_REQUIRE_UNARY(isSetup2);
    }
  }
  tanker_destroy(tanker);
}

TEST_CASE("Test functionalities")
{
  TestTrustchain trustchain;

  // Setup everything
  auto tanker = create_user(trustchain);

  // Test Here
  SUBCASE("device_id should return a correct base64 string")
  {
    auto device_id_fut = tanker_device_id(tanker);

    tanker_future_wait(device_id_fut);
    CHECK_FALSE(tanker_future_has_error(device_id_fut));

    auto device_id =
        static_cast<b64char*>(tanker_future_get_voidptr(device_id_fut));
    tanker_future_destroy(device_id_fut);

    auto const device_id_size = std::strlen(device_id);
    auto const max_decoded_size =
        tanker_base64_decoded_max_size(device_id_size);
    std::vector<char> decoded(max_decoded_size);
    auto decode_expected = tanker_base64_decode(
        decoded.data(), nullptr, device_id, device_id_size);

    CHECK_FALSE(tanker_future_has_error(decode_expected));

    tanker_future_destroy(decode_expected);
    tanker_free_buffer(device_id);
  }

  SUBCASE("Encrypt/Decrypt")
  {
    uint8_t const buf[] = "I am a test, test, test!";
    size_t const encryptedSize = tanker_encrypted_size(sizeof(buf));
    uint8_t* encryptedBuffer =
        (uint8_t*)malloc(encryptedSize * sizeof(*encryptedBuffer));
    tanker_encrypt_options_t encrypt_options = TANKER_ENCRYPT_OPTIONS_INIT;
    tanker_future_t* future_encrypt = tanker_encrypt(
        tanker, encryptedBuffer, buf, sizeof(buf), &encrypt_options);

    tanker_future_wait(future_encrypt);
    REQUIRE(tanker_future_has_error(future_encrypt) == 0);

    SUBCASE("Get ressource id")
    {
      tanker_future_t* future_res_id =
          tanker_get_resource_id(encryptedBuffer, encryptedSize);
      tanker_future_wait(future_res_id);
      REQUIRE(tanker_future_has_error(future_res_id) == 0);

      b64char* resId = (b64char*)tanker_future_get_voidptr(future_res_id);
      tanker_free_buffer(resId);
      tanker_future_destroy(future_res_id);
    }

    tanker_expected_t* expectedDecryptedSize =
        tanker_decrypted_size(encryptedBuffer, encryptedSize);
    tanker_future_wait(expectedDecryptedSize);

    REQUIRE(tanker_future_has_error(expectedDecryptedSize) == 0);

    SUBCASE("decrypt")
    {
      uint64_t const decryptedSize =
          (uint64_t)tanker_future_get_voidptr(expectedDecryptedSize);
      uint8_t* decryptedBuffer =
          (uint8_t*)malloc(decryptedSize * sizeof(*decryptedBuffer));
      tanker_future_t* future_decrypt = tanker_decrypt(
          tanker, decryptedBuffer, encryptedBuffer, encryptedSize, NULL);
      tanker_future_wait(future_decrypt);

      REQUIRE(tanker_future_has_error(future_decrypt) == 0);
      CHECK(decryptedSize == sizeof(buf));
      CHECK(memcmp(decryptedBuffer, buf, sizeof(buf)) == 0);

      tanker_future_destroy(future_decrypt);
      free(decryptedBuffer);
    }

    tanker_future_destroy(expectedDecryptedSize);
    tanker_future_destroy(future_encrypt);
    free(encryptedBuffer);
  }

  SUBCASE("ChunkEncryptor")
  {
    uint8_t const buf[] = "This is a very very secret message!";
    size_t const encrypted_size =
        tanker_chunk_encryptor_encrypted_size(sizeof(buf));
    uint8_t* encrypted_buffer =
        (uint8_t*)malloc(encrypted_size * sizeof(*encrypted_buffer));
    tanker_encrypt_options_t encrypt_options = TANKER_ENCRYPT_OPTIONS_INIT;

    // Create an empty chunkEncryptor
    tanker_future_t* future_chunk = tanker_make_chunk_encryptor(tanker);
    tanker_future_wait(future_chunk);
    REQUIRE(tanker_future_has_error(future_chunk) == 0);
    tanker_chunk_encryptor_t* chunk_encryptor =
        (tanker_chunk_encryptor_t*)tanker_future_get_voidptr(future_chunk);
    tanker_future_destroy(future_chunk);

    // Append
    tanker_future_t* future_append = tanker_chunk_encryptor_encrypt_append(
        chunk_encryptor, encrypted_buffer, buf, sizeof(buf));
    tanker_future_wait(future_append);
    REQUIRE(tanker_future_has_error(future_append) == 0);
    CHECK(tanker_chunk_encryptor_chunk_count(chunk_encryptor) == 1);
    tanker_future_destroy(future_append);

    // EncryptAt
    tanker_future_t* future_encrypt_at = tanker_chunk_encryptor_encrypt_at(
        chunk_encryptor, encrypted_buffer, buf, sizeof(buf), 3);
    tanker_future_wait(future_encrypt_at);
    REQUIRE(tanker_future_has_error(future_encrypt_at) == 0);
    CHECK(tanker_chunk_encryptor_chunk_count(chunk_encryptor) == 4);
    tanker_future_destroy(future_encrypt_at);

    // Decrypt
    tanker_future_t* future_decrypted_size =
        tanker_chunk_encryptor_decrypted_size(encrypted_buffer, encrypted_size);
    size_t const decrypted_size =
        (size_t)tanker_future_get_voidptr(future_decrypted_size);
    uint8_t* decrypted_buffer =
        (uint8_t*)malloc(decrypted_size * sizeof(*decrypted_buffer));
    tanker_future_t* future_decrypt = tanker_chunk_encryptor_decrypt(
        chunk_encryptor, decrypted_buffer, encrypted_buffer, encrypted_size, 3);
    tanker_future_wait(future_decrypt);
    REQUIRE(tanker_future_has_error(future_decrypt) == 0);
    CHECK(memcmp(decrypted_buffer, buf, sizeof(buf)) == 0);
    free(decrypted_buffer);
    tanker_future_destroy(future_decrypt);
    tanker_future_destroy(future_decrypted_size);

    // Remove
    uint64_t const indexes[] = {2};
    tanker_future_t* future_remove =
        tanker_chunk_encryptor_remove(chunk_encryptor, indexes, 1);
    tanker_future_wait(future_remove);
    REQUIRE(tanker_future_has_error(future_remove) == 0);
    CHECK(tanker_chunk_encryptor_chunk_count(chunk_encryptor) == 3);
    tanker_future_destroy(future_remove);

    // Seal
    size_t const seal_size = tanker_chunk_encryptor_seal_size(chunk_encryptor);
    uint8_t* seal = (uint8_t*)malloc(seal_size * sizeof(*seal));
    tanker_future_t* future_seal =
        tanker_chunk_encryptor_seal(chunk_encryptor, seal, &encrypt_options);
    tanker_future_wait(future_seal);
    REQUIRE(tanker_future_has_error(future_seal) == 0);
    tanker_future_destroy(future_seal);

    // Create chunkEncryptor from seal
    tanker_decrypt_options_t decrypt_options = TANKER_DECRYPT_OPTIONS_INIT;
    tanker_future_t* future_chunk_from_seal =
        tanker_make_chunk_encryptor_from_seal(
            tanker, seal, seal_size, &decrypt_options);
    tanker_future_wait(future_chunk_from_seal);
    REQUIRE(tanker_future_has_error(future_chunk_from_seal) == 0);
    tanker_chunk_encryptor_t* chunk_encryptor_from_seal =
        (tanker_chunk_encryptor_t*)tanker_future_get_voidptr(
            future_chunk_from_seal);
    tanker_future_destroy(future_chunk_from_seal);

    CHECK(tanker_chunk_encryptor_chunk_count(chunk_encryptor) ==
          tanker_chunk_encryptor_chunk_count(chunk_encryptor_from_seal));
    CHECK(tanker_chunk_encryptor_seal_size(chunk_encryptor) ==
          tanker_chunk_encryptor_seal_size(chunk_encryptor_from_seal));

    tanker_future_t* future_destroy =
        tanker_chunk_encryptor_destroy(chunk_encryptor);
    tanker_future_destroy(future_destroy);
    tanker_future_t* future_destroy_from_seal =
        tanker_chunk_encryptor_destroy(chunk_encryptor_from_seal);
    tanker_future_destroy(future_destroy_from_seal);
    free(encrypted_buffer);
    free(seal);
  }

  tanker_future_t* future_destroy = tanker_destroy(tanker);
  tanker_future_wait(future_destroy);
  tanker_future_destroy(future_destroy);
}
