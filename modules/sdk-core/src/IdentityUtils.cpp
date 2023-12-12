#include <Tanker/IdentityUtils.hpp>

#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Identity/Extract.hpp>
#include <Tanker/Utils.hpp>

#include <range/v3/algorithm/equal.hpp>
#include <range/v3/algorithm/find_if.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/cycle.hpp>
#include <range/v3/view/single.hpp>
#include <range/v3/view/transform.hpp>

#include <boost/variant2/variant.hpp>

namespace Tanker
{
Identity::PublicIdentity extractPublicIdentity(SPublicIdentity const& spublicIdentity)
{
  try
  {
    return Identity::extract<Identity::PublicIdentity>(spublicIdentity.string());
  }
  catch (Errors::Exception const& e)
  {
    throw Errors::formatEx(
        e.errorCode(), "invalid public identity {}", fmt::make_format_args(spublicIdentity.string()));
  }
}

PartitionedIdentities partitionIdentities(std::vector<Identity::PublicIdentity> const& identities)
{
  PartitionedIdentities out;
  for (auto const& identity : identities)
  {
    if (auto const i = boost::variant2::get_if<Identity::PublicPermanentIdentity>(&identity))
      out.userIds.push_back(i->userId);
    else if (auto const i = boost::variant2::get_if<Identity::PublicProvisionalIdentity>(&identity))
      out.publicProvisionalIdentities.push_back(*i);
    else
      throw Errors::AssertionError("unknown variant value in identity");
  }
  return out;
}

namespace
{
auto findErrorPred(Trustchain::UserId const& errId)
{
  return [&](auto const& id) {
    if (auto const permId = boost::variant2::get_if<Identity::PublicPermanentIdentity>(&id))
      return permId->userId == errId;
    return false;
  };
}

auto findErrorPred(Trustchain::ProvisionalUserId const& errId)
{
  return [&](auto const& id) {
    if (auto const provisionalId = boost::variant2::get_if<Identity::PublicProvisionalIdentity>(&id))
      return provisionalId->appSignaturePublicKey == errId.appSignaturePublicKey();
    return false;
  };
}

auto errorIdToClearId(std::vector<SPublicIdentity> const& sIds, std::vector<Identity::PublicIdentity> const& ids)
{
  return [&](auto const& errId) {
    auto const it = ranges::find_if(ids, findErrorPred(errId));
    if (it == ranges::end(ids))
    {
      if constexpr (std::is_same_v<decltype(errId), Trustchain::UserId const>)
        throw Errors::AssertionError("identities not found");
      else
        throw Errors::AssertionError("provisional identities not found");
    }
    return sIds[it - ids.begin()];
  };
}
}

std::vector<SPublicIdentity> mapIdentitiesToStrings(std::vector<Trustchain::UserId> const& errorIds,
                                                    std::vector<SPublicIdentity> const& sIds,
                                                    std::vector<Identity::PublicIdentity> const& ids)

{
  return errorIds | ranges::views::transform(errorIdToClearId(sIds, ids)) | ranges::to<std::vector>;
}

std::vector<SPublicIdentity> mapIdentitiesToStrings(std::vector<Trustchain::ProvisionalUserId> const& errorIds,
                                                    std::vector<SPublicIdentity> const& sIds,
                                                    std::vector<Identity::PublicIdentity> const& ids)
{
  return errorIds | ranges::views::transform(errorIdToClearId(sIds, ids)) | ranges::to<std::vector>;
}
}
