#include <Tanker/AsyncCore.hpp>
#include <Tanker/Functional/Device.hpp>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
inline tc::cotask<std::vector<uint8_t>> encrypt(
    AsyncCore& core,
    std::string const& data,
    std::vector<SPublicIdentity> const& publicIdentities = {},
    std::vector<SGroupId> const& groupIds = {},
    std::optional<uint32_t> paddingStep = std::nullopt)
{
  TC_RETURN(TC_AWAIT(core.encrypt(make_buffer(data),
                                  publicIdentities,
                                  groupIds,
                                  Core::ShareWithSelf::Yes,
                                  paddingStep)));
}

inline tc::cotask<std::string> decrypt(
    AsyncCore& core, std::vector<uint8_t> const& encryptedData)
{
  auto const decrypted = TC_AWAIT(core.decrypt(encryptedData));
  TC_RETURN(std::string(decrypted.begin(), decrypted.end()));
}

inline tc::cotask<void> checkDecrypt(
    std::vector<Functional::AsyncCorePtr> const& sessions,
    std::string const& clearData,
    std::vector<uint8_t> const& encryptedData)
{
  for (auto const& session : sessions)
  {
    std::vector<uint8_t> decryptedData =
        TC_AWAIT(session->decrypt(encryptedData));
    if (gsl::make_span(decryptedData) !=
        gsl::make_span(clearData).as_span<uint8_t const>())
      throw std::runtime_error("checkDecrypt: decrypted data doesn't match");
  }
}
}
