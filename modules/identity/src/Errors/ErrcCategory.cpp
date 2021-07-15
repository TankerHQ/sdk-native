#include <Tanker/Identity/Errors/ErrcCategory.hpp>

#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Identity/Errors/Errc.hpp>

namespace Tanker
{
namespace Identity
{
namespace detail
{
std::string ErrcCategory::message(int c) const
{
  switch (static_cast<Errc>(c))
  {
  case Errc::InvalidUserId:
    return "invalid user id";
  case Errc::InvalidTrustchainId:
    return "invalid trustchain id";
  case Errc::InvalidTrustchainPrivateKey:
    return "invalid trustchain private key";
  case Errc::InvalidPermanentIdentityTarget:
    return "invalid permanent identity target";
  case Errc::InvalidProvisionalIdentityTarget:
    return "invalid provisional identity target";
  case Errc::InvalidUserSecret:
    return "invalid user secret";
  case Errc::InvalidEmail:
    return "invalid email address";
  case Errc::InvalidType:
    return "invalid identity type";
  case Errc::InvalidFormat:
    return "invalid identity format";
  case Errc::InvalidPhoneNumber:
    return "invalid phone number";
  default:
    return "unknown error";
  }
}

std::error_condition ErrcCategory::default_error_condition(int c) const noexcept
{
  switch (static_cast<Errc>(c))
  {
  case Errc::InvalidUserId:
  case Errc::InvalidTrustchainId:
  case Errc::InvalidTrustchainPrivateKey:
  case Errc::InvalidPermanentIdentityTarget:
  case Errc::InvalidProvisionalIdentityTarget:
  case Errc::InvalidUserSecret:
  case Errc::InvalidEmail:
  case Errc::InvalidType:
  case Errc::InvalidFormat:
  case Errc::InvalidPhoneNumber:
    return make_error_condition(Errors::Errc::InvalidArgument);
  default:
    return std::error_condition(c, *this);
  }
}
}
}
}
