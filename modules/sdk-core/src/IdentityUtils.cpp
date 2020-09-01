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
}
