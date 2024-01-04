#include <Tanker/ProvisionalUsers/Updater.hpp>

#include <Tanker/Crypto/Crypto.hpp>
#include <Tanker/Crypto/Format/Format.hpp>
#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Log/Log.hpp>
#include <Tanker/ProvisionalUsers/Verif/ProvisionalIdentityClaim.hpp>
#include <Tanker/Trustchain/Actions/ProvisionalIdentityClaim.hpp>
#include <Tanker/Users/Device.hpp>
#include <Tanker/Users/ILocalUserAccessor.hpp>
#include <Tanker/Users/IUserAccessor.hpp>
#include <Tanker/Verif/Errors/Errc.hpp>
#include <Tanker/Verif/Errors/ErrcCategory.hpp>
#include <Tanker/Verif/Helpers.hpp>

#include <boost/container/flat_map.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

#include <algorithm>

TLOG_CATEGORY("ProvisionalUsersUpdater");

using Tanker::Trustchain::Actions::ProvisionalIdentityClaim;
using namespace Tanker::Errors;

namespace Tanker
{
namespace ProvisionalUsers
{
namespace Updater
{
namespace
{
using DeviceMap = boost::container::flat_map<Trustchain::DeviceId, Users::Device>;

tc::cotask<DeviceMap> extractAuthors(Users::IUserAccessor& userAccessor,
                                     gsl::span<Trustchain::Actions::ProvisionalIdentityClaim const> entries)
{
  DeviceMap out;

  auto authors = entries |
                 ranges::views::transform([](auto const& action) { return Trustchain::DeviceId{action.author()}; }) |
                 ranges::to<std::vector>;
  auto const pullResult = TC_AWAIT(userAccessor.pull(authors));
  if (!pullResult.notFound.empty())
  {
    // we should have all the devices because they are *our* devices
    throw Errors::formatEx(Errors::Errc::InternalError,
                           "missing device(s) for claim verification: {}",
                           fmt::join(pullResult.notFound, ", "));
  }

  for (auto const& device : pullResult.found)
    out.emplace(device.id(), device);

  TC_RETURN(out);
}
}

tc::cotask<UsedSecretUser> extractKeysToStore(Users::ILocalUserAccessor& localUserAccessor,
                                              ProvisionalIdentityClaim const& provisionalIdentityClaim)
{
  auto const userKeyPair =
      TC_AWAIT(localUserAccessor.pullUserKeyPair(provisionalIdentityClaim.userPublicEncryptionKey()));

  if (!userKeyPair)
    throw Exception(make_error_code(Errc::InternalError), "cannot find user key for claim decryption");

  auto const provisionalIdentityKeys =
      Crypto::sealDecrypt(provisionalIdentityClaim.sealedPrivateEncryptionKeys(), *userKeyPair);

  // this size is ensured because the encrypted buffer has a fixed size
  assert(provisionalIdentityKeys.size() == 2 * Crypto::PrivateEncryptionKey::arraySize);

  auto const appEncryptionKeyPair = Crypto::makeEncryptionKeyPair(Crypto::PrivateEncryptionKey(
      gsl::make_span(provisionalIdentityKeys).subspan(0, Crypto::PrivateEncryptionKey::arraySize)));
  auto const tankerEncryptionKeyPair = Crypto::makeEncryptionKeyPair(Crypto::PrivateEncryptionKey(
      gsl::make_span(provisionalIdentityKeys).subspan(Crypto::PrivateEncryptionKey::arraySize)));

  TC_RETURN((UsedSecretUser{provisionalIdentityClaim.appSignaturePublicKey(),
                            provisionalIdentityClaim.tankerSignaturePublicKey(),
                            appEncryptionKeyPair,
                            tankerEncryptionKeyPair}));
}

tc::cotask<std::vector<UsedSecretUser>> processClaimEntries(
    Users::ILocalUserAccessor& localUserAccessor,
    Users::IUserAccessor& userAccessor,
    gsl::span<Trustchain::Actions::ProvisionalIdentityClaim const> actions)
{
  auto const authors = TC_AWAIT(extractAuthors(userAccessor, actions));

  std::vector<UsedSecretUser> out;
  for (auto const& action : actions)
  {
    auto const authorIt = authors.find(Trustchain::DeviceId{action.author()});
    Verif::ensures(authorIt != authors.end(), Verif::Errc::InvalidAuthor, "author not found");
    auto const& author = authorIt->second;

    auto const verifiedAction = Verif::verifyProvisionalIdentityClaim(action, author);

    out.push_back(TC_AWAIT(extractKeysToStore(localUserAccessor, verifiedAction)));
  }
  TC_RETURN(out);
}
}
}
}
