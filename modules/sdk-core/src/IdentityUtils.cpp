#include <Tanker/IdentityUtils.hpp>

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Utils.hpp>

namespace Tanker
{
std::vector<Identity::PublicIdentity> extractPublicIdentities(
    std::vector<SPublicIdentity> const& spublicIdentities)
{
  return convertList(spublicIdentities, [](auto&& spublicIdentity) {
    try
    {
      return Identity::extract<Identity::PublicIdentity>(
          spublicIdentity.string());
    }
    catch (Errors::Exception const& e)
    {
      throw Errors::formatEx(e.errorCode(),
                             "invalid public identity {}",
                             fmt::make_format_args(spublicIdentity.string()));
    }
  });
}

PartitionedIdentities partitionIdentities(
    std::vector<Identity::PublicIdentity> const& identities)
{
  PartitionedIdentities out;
  for (auto const& identity : identities)
  {
    if (auto const i =
            boost::variant2::get_if<Identity::PublicPermanentIdentity>(
                &identity))
      out.userIds.push_back(i->userId);
    else if (auto const i =
                 boost::variant2::get_if<Identity::PublicProvisionalIdentity>(
                     &identity))
      out.publicProvisionalIdentities.push_back(*i);
    else
      throw Errors::AssertionError("unknown variant value in identity");
  }
  return out;
}

std::vector<SPublicIdentity> mapIdentitiesToStrings(
    std::vector<Trustchain::UserId> const& errorIds,
    std::vector<SPublicIdentity> const& sIds,
    std::vector<Identity::PublicIdentity> const& ids)

{
  std::vector<SPublicIdentity> clearIds;
  clearIds.reserve(ids.size());
  for (auto const& errorId : errorIds)
  {
    using boost::variant2::get_if;
    auto const idsIt =
        std::find_if(ids.begin(), ids.end(), [&](auto const& id) {
          if (auto const permId =
                  get_if<Identity::PublicPermanentIdentity>(&id))
            return permId->userId == errorId;
          return false;
        });

    if (idsIt == ids.end())
      throw Errors::AssertionError("identities not found");

    clearIds.push_back(sIds[std::distance(ids.begin(), idsIt)]);
  }
  return clearIds;
}
}
