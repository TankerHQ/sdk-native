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
  MAKE_MOCK0(getMe, tc::cotask<GetMeResult>(), override);
  MAKE_MOCK3(
      authenticateSocketIO,
      tc::cotask<void>(Trustchain::TrustchainId const& trustchainId,
                       Trustchain::UserId const& userId,
                       Crypto::SignatureKeyPair const& userSignatureKeyPair),
      override);
  MAKE_MOCK2(
      authenticate,
      tc::cotask<void>(Trustchain::DeviceId const& userId,
                       Crypto::SignatureKeyPair const& userSignatureKeyPair),
      override);
  MAKE_MOCK1(getUsers,
             tc::cotask<std::vector<Trustchain::UserAction>>(
                 gsl::span<Trustchain::UserId const> userIds),
             override);
  MAKE_MOCK1(getUsers,
             tc::cotask<std::vector<Trustchain::UserAction>>(
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
