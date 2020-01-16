#pragma once

#include <Tanker/Trustchain/TrustchainId.hpp>
#include <Tanker/Trustchain/UserId.hpp>
#include <Tanker/Users/IRequester.hpp>

#include <trompeloeil.hpp>

namespace Tanker
{
class UserRequesterStub : public Users::IRequester
{
public:
  MAKE_MOCK0(getMe,
             tc::cotask<std::vector<Trustchain::ServerEntry>>(),
             override);
  MAKE_MOCK3(userStatus,
             tc::cotask<Users::UserStatusResult>(
                 Trustchain::TrustchainId const& trustchainId,
                 Trustchain::UserId const& userId,
                 Crypto::PublicSignatureKey const& publicSignatureKey),
             override);
  MAKE_MOCK3(
      authenticate,
      tc::cotask<void>(Trustchain::TrustchainId const& trustchainId,
                       Trustchain::UserId const& userId,
                       Crypto::SignatureKeyPair const& userSignatureKeyPair),
      override);
  MAKE_MOCK1(getUsers,
             tc::cotask<std::vector<Trustchain::ServerEntry>>(
                 gsl::span<Trustchain::UserId const> userIds),
             override);
  MAKE_MOCK1(getUsers,
             tc::cotask<std::vector<Trustchain::ServerEntry>>(
                 gsl::span<Trustchain::DeviceId const> deviceIds),
             override);
  MAKE_MOCK1(getPublicProvisionalIdentities,
             (tc::cotask<std::vector<std::tuple<Crypto::PublicSignatureKey,
                                                Crypto::PublicEncryptionKey>>>(
                 gsl::span<Email const>)),
             override);
};
}
