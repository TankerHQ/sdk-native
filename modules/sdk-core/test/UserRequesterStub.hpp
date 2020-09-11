#pragma once

#include <Tanker/Trustchain/DeviceId.hpp>
#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/IRequester.hpp>

#include <trompeloeil.hpp>

namespace Tanker
{
class UserRequesterStub : public Users::IRequester
{
public:
  MAKE_MOCK1(postResourceKeys,
             tc::cotask<void>(Share::ShareActions const&),
             override);
  MAKE_MOCK1(revokeDevice,
             tc::cotask<void>(
                 Trustchain::Actions::DeviceRevocation const& deviceRevocation),
             override);
  MAKE_MOCK2(
      getEncryptionKey,
      tc::cotask<IRequester::GetEncryptionKeyResult>(
          Trustchain::UserId const& userId,
          Crypto::PublicSignatureKey const& ghostDevicePublicSignatureKey),
      override);
  MAKE_MOCK1(getRevokedDeviceHistory,
             tc::cotask<Users::IRequester::GetResult>(
                 Trustchain::DeviceId const& deviceId),
             override);
  MAKE_MOCK1(getUsers,
             tc::cotask<Users::IRequester::GetResult>(
                 gsl::span<Trustchain::UserId const> userIds),
             override);
  MAKE_MOCK1(getUsers,
             tc::cotask<Users::IRequester::GetResult>(
                 gsl::span<Trustchain::DeviceId const> deviceIds),
             override);
  MAKE_MOCK1(getKeyPublishes,
             tc::cotask<std::vector<Trustchain::KeyPublishAction>>(
                 gsl::span<Trustchain::ResourceId const> resourceIds),
             override);
  MAKE_MOCK1(getPublicProvisionalIdentities,
             (tc::cotask<std::map<Crypto::Hash,
                                  std::pair<Crypto::PublicSignatureKey,
                                            Crypto::PublicEncryptionKey>>>(
                 gsl::span<Crypto::Hash const>)),
             override);
};
}
