#pragma once

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Functional/Device.hpp>

#include <catch2/catch.hpp>

#include <tconcurrent/coroutine.hpp>

#include <initializer_list>

namespace Tanker
{
inline tc::cotask<std::vector<uint8_t>> encrypt(
    AsyncCore& core,
    std::string const& data,
    std::vector<SPublicIdentity> const& publicIdentities = {},
    std::vector<SGroupId> const& groupIds = {})
{
  TC_RETURN(
      TC_AWAIT(core.encrypt(make_buffer(data), publicIdentities, groupIds)));
}

inline tc::cotask<std::string> decrypt(
    AsyncCore& core, std::vector<uint8_t> const& encryptedData)
{
  auto const decrypted = TC_AWAIT(core.decrypt(encryptedData));
  TC_RETURN(std::string(decrypted.begin(), decrypted.end()));
}

struct EncryptedBuffer
{
  std::vector<uint8_t> clearData;
  std::vector<uint8_t> encryptedData;
};

inline tc::cotask<EncryptedBuffer> encrypt(
    AsyncCore& core,
    std::vector<SPublicIdentity> const& publicIdentities = {},
    std::vector<SGroupId> const& groupIds = {})
{
  std::vector<uint8_t> clearData(24); // arbitrary size
  Crypto::randomFill(clearData);
  auto encryptedData =
      TC_AWAIT(core.encrypt(clearData, publicIdentities, groupIds));
  TC_RETURN((EncryptedBuffer{std::move(clearData), std::move(encryptedData)}));
}

inline tc::cotask<void> checkDecrypt(
    std::vector<Functional::AsyncCorePtr> const& sessions,
    std::string const& clearData,
    std::vector<uint8_t> const& encryptedData)
{
  for (auto const& session : sessions)
  {
    std::vector<uint8_t> decryptedData;
    REQUIRE_NOTHROW(decryptedData = TC_AWAIT(session->decrypt(encryptedData)));
    REQUIRE(gsl::make_span(decryptedData) ==
            gsl::make_span(clearData).as_span<uint8_t const>());
  }
}

template <typename T>
tc::cotask<void> checkDecrypt(std::initializer_list<T> userSessions,
                              std::vector<EncryptedBuffer> const& buffers)
{
  TC_AWAIT(checkDecrypt<std::initializer_list<T>>(userSessions, buffers));
}

template <typename T>
tc::cotask<void> checkDecrypt(T const& userSessions,
                              std::vector<EncryptedBuffer> const& buffers)
{
  for (auto const& userSession : userSessions)
    for (auto const& buffer : buffers)
    {
      std::vector<uint8_t> decryptedData;
      REQUIRE_NOTHROW(decryptedData = TC_AWAIT(
                          userSession.session->decrypt(buffer.encryptedData)));
      REQUIRE(decryptedData == buffer.clearData);
    }
}

template <typename T>
tc::cotask<void> checkDecryptFails(std::initializer_list<T> userSessions,
                                   std::vector<EncryptedBuffer> const& buffers)
{
  TC_AWAIT(checkDecryptFails<std::initializer_list<T>>(userSessions, buffers));
}

template <typename T>
tc::cotask<void> checkDecryptFails(T const& userSessions,
                                   std::vector<EncryptedBuffer> const& buffers)
{
  for (auto const& userSession : userSessions)
    for (auto const& buffer : buffers)
    {
      TANKER_CHECK_THROWS_WITH_CODE_AND_MESSAGE(
          TC_AWAIT(userSession.session->decrypt(buffer.encryptedData)),
          Tanker::Errors::Errc::InvalidArgument,
          "can't find keys for resource");
    }
}
}
