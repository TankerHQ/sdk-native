#include <Tanker/AsyncCore.hpp>
#include <Tanker/Test/Functional/Device.hpp>
#include <tconcurrent/coroutine.hpp>

namespace Tanker
{
inline tc::cotask<std::vector<uint8_t>> encrypt(
    AsyncCore& core,
    std::string const& data,
    std::vector<SPublicIdentity> const& publicIdentities = {},
    std::vector<SGroupId> const& groupIds = {})
{
  auto const clearData = make_buffer(data);
  std::vector<uint8_t> encryptedData(
      AsyncCore::encryptedSize(clearData.size()));
  TC_AWAIT(core.encrypt(
      encryptedData.data(), clearData, publicIdentities, groupIds));
  TC_RETURN(encryptedData);
}

inline tc::cotask<std::string> decrypt(
    AsyncCore& core, std::vector<uint8_t> const& encryptedData)
{
  std::vector<uint8_t> decryptedData(
      AsyncCore::decryptedSize(encryptedData).get());
  TC_AWAIT(core.decrypt(decryptedData.data(), encryptedData));
  TC_RETURN(std::string(decryptedData.begin(), decryptedData.end()));
}

inline tc::cotask<bool> checkDecrypt(
    std::vector<Test::Device> devices,
    std::vector<std::tuple<std::vector<uint8_t>, std::vector<uint8_t>>> const&
        metas)
{
  for (auto& tanker : devices)
  {
    auto session = TC_AWAIT(tanker.open());
    for (auto const& meta : metas)
    {
      auto const& clearData = std::get<0>(meta);
      auto const& encryptedData = std::get<1>(meta);
      std::vector<uint8_t> decryptedData(
          AsyncCore::decryptedSize(encryptedData).get());
      TC_AWAIT(session->decrypt(decryptedData.data(), encryptedData));
      if (decryptedData != clearData)
        TC_RETURN(false);
    }
  }
  TC_RETURN(true);
}
}
