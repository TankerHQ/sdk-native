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
  MAKE_MOCK2(
      getEncryptionKey,
      tc::cotask<IRequester::GetEncryptionKeyResult>(
          Trustchain::UserId const& userId,
          Crypto::PublicSignatureKey const& ghostDevicePublicSignatureKey),
      override);
  MAKE_MOCK2(getUsers,
             tc::cotask<Users::IRequester::GetResult>(
                 gsl::span<Trustchain::UserId const> userIds, IsLight isLight),
             override);
  MAKE_MOCK2(getUsers,
             tc::cotask<Users::IRequester::GetResult>(
                 gsl::span<Trustchain::DeviceId const> deviceIds,
                 IsLight isLight),
             override);
  MAKE_MOCK1(getKeyPublishes,
             tc::cotask<std::vector<Trustchain::KeyPublishAction>>(
                 gsl::span<Crypto::SimpleResourceId const> resourceIds),
             override);
  MAKE_MOCK1(getPublicProvisionalIdentities,
             (tc::cotask<std::map<HashedEmail,
                                  std::pair<Crypto::PublicSignatureKey,
                                            Crypto::PublicEncryptionKey>>>(
                 gsl::span<HashedEmail const>)),
             override);
  MAKE_MOCK1(getPublicProvisionalIdentities,
             (tc::cotask<std::map<HashedPhoneNumber,
                                  std::pair<Crypto::PublicSignatureKey,
                                            Crypto::PublicEncryptionKey>>>(
                 gsl::span<HashedPhoneNumber const>)),
             override);
};
}
