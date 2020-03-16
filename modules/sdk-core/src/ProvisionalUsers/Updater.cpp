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
using DeviceMap =
    boost::container::flat_map<Trustchain::DeviceId, Users::Device>;

tc::cotask<DeviceMap> extractAuthors(
    Users::IUserAccessor& contactAccessor,
    gsl::span<Trustchain::ServerEntry const> entries)
{
  DeviceMap out;

  std::vector<Trustchain::DeviceId> authors(entries.size());
  std::transform(
      std::begin(entries),
      std::end(entries),
      std::begin(authors),
      [](auto const& entry) { return Trustchain::DeviceId{entry.author()}; });
  auto const pullResult = TC_AWAIT(contactAccessor.pull(authors));
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

tc::cotask<UsedSecretUser> extractKeysToStore(
    Users::ILocalUserAccessor& localUserAccessor, Entry const& entry)
{
  auto const& provisionalIdentityClaim =
      entry.action.get<ProvisionalIdentityClaim>();

  auto const userKeyPair = TC_AWAIT(localUserAccessor.pullUserKeyPair(
      provisionalIdentityClaim.userPublicEncryptionKey()));

  if (!userKeyPair)
    throw Exception(make_error_code(Errc::InternalError),
                    "cannot find user key for claim decryption");

  auto const provisionalIdentityKeys = Crypto::sealDecrypt(
      provisionalIdentityClaim.sealedPrivateEncryptionKeys(), *userKeyPair);

  // this size is ensured because the encrypted buffer has a fixed size
  assert(provisionalIdentityKeys.size() ==
         2 * Crypto::PrivateEncryptionKey::arraySize);

  auto const appEncryptionKeyPair =
      Crypto::makeEncryptionKeyPair(Crypto::PrivateEncryptionKey(
          gsl::make_span(provisionalIdentityKeys)
              .subspan(0, Crypto::PrivateEncryptionKey::arraySize)));
  auto const tankerEncryptionKeyPair =
      Crypto::makeEncryptionKeyPair(Crypto::PrivateEncryptionKey(
          gsl::make_span(provisionalIdentityKeys)
              .subspan(Crypto::PrivateEncryptionKey::arraySize)));

  TC_RETURN((UsedSecretUser{provisionalIdentityClaim.appSignaturePublicKey(),
                            provisionalIdentityClaim.tankerSignaturePublicKey(),
                            appEncryptionKeyPair,
                            tankerEncryptionKeyPair}));
}

tc::cotask<std::vector<UsedSecretUser>> processClaimEntries(
    Users::ILocalUserAccessor& localUserAccessor,
    Users::IUserAccessor& contactAccessor,
    gsl::span<Trustchain::ServerEntry const> serverEntries)
{
  auto const authors = TC_AWAIT(extractAuthors(contactAccessor, serverEntries));

  std::vector<UsedSecretUser> out;
  for (auto const& serverEntry : serverEntries)
  {
    try
    {
      auto const authorIt =
          authors.find(Trustchain::DeviceId{serverEntry.author()});
      Verif::ensures(authorIt != authors.end(),
                     Verif::Errc::InvalidAuthor,
                     "author not found");
      auto const& author = authorIt->second;
      if (!serverEntry.action().holds_alternative<ProvisionalIdentityClaim>())
        throw Errors::AssertionError(fmt::format(
            "cannot handle nature: {}", serverEntry.action().nature()));

      auto const entry =
          Verif::verifyProvisionalIdentityClaim(serverEntry, author);

      out.push_back(TC_AWAIT(extractKeysToStore(localUserAccessor, entry)));
    }
    catch (Errors::Exception const& err)
    {
      if (err.errorCode().category() == Verif::ErrcCategory())
      {
        TERROR("skipping invalid claim block {}: {}",
               serverEntry.hash(),
               err.what());
      }
      else
        throw;
    }
  }
  TC_RETURN(out);
}
}
}
}
