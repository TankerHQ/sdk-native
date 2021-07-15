#include <Tanker/Errors/AssertionError.hpp>
#include <Tanker/Errors/Errc.hpp>
#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Identity/TargetType.hpp>
#include <boost/algorithm/string.hpp>

namespace Tanker::Identity
{
std::string to_string(TargetType t)
{
  switch (t)
  {
  case TargetType::Email:
    return "email";
  case TargetType::HashedEmail:
    return "hashed_email";
  case TargetType::PhoneNumber:
    return "phone_number";
  case TargetType::HashedPhoneNumber:
    return "hashed_phone_number";
  }
  throw Errors::AssertionError("Unhandled type in to_string(TargetType)");
}

TargetType to_target_type(std::string const& s)
{
  if (s == "email")
    return TargetType::Email;
  else if (s == "hashed_email")
    return TargetType::HashedEmail;
  if (s == "phone_number")
    return TargetType::PhoneNumber;
  else if (s == "hashed_phone_number")
    return TargetType::HashedPhoneNumber;
  else
    throw Errors::formatEx(Errors::Errc::InvalidArgument,
                           "Invalid identity target type: " + s);
}
}
