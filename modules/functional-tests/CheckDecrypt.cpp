#include "CheckDecrypt.hpp"

#include <Tanker/AsyncCore.hpp>
#include <Tanker/Functional/Device.hpp>

#include <Helpers/Buffers.hpp>

#include <catch2/catch.hpp>

#include <tconcurrent/coroutine.hpp>

#include <initializer_list>

namespace Tanker
{
tc::cotask<std::vector<uint8_t>> encrypt(
    AsyncCore& core,
    std::string const& data,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds,
    std::optional<uint32_t> paddingStep)
{
  TC_RETURN(TC_AWAIT(core.encrypt(make_buffer(data),
                                  publicIdentities,
                                  groupIds,
                                  Core::ShareWithSelf::Yes,
                                  paddingStep)));
}

tc::cotask<std::string> decrypt(AsyncCore& core,
                                std::vector<uint8_t> const& encryptedData)
{
  auto const decrypted = TC_AWAIT(core.decrypt(encryptedData));
  TC_RETURN(std::string(decrypted.begin(), decrypted.end()));
}

tc::cotask<EncryptedBuffer> encrypt(
    AsyncCore& core,
    std::vector<SPublicIdentity> const& publicIdentities,
    std::vector<SGroupId> const& groupIds)
{
  std::vector<uint8_t> clearData(24); // arbitrary size
  Crypto::randomFill(clearData);
  auto encryptedData =
      TC_AWAIT(core.encrypt(clearData, publicIdentities, groupIds));
  TC_RETURN((EncryptedBuffer{std::move(clearData), std::move(encryptedData)}));
}

tc::cotask<void> checkDecrypt(
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
}
