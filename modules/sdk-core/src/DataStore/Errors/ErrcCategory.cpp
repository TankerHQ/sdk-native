#include <Tanker/DataStore/Errors/ErrcCategory.hpp>

#include <Tanker/DataStore/Errors/Errc.hpp>
#include <Tanker/Errors/Errc.hpp>

namespace Tanker
{
namespace DataStore
{
namespace detail
{
std::string ErrcCategory::message(int c) const
{
  switch (static_cast<Errc>(c))
  {
  case Errc::InvalidDatabaseVersion:
    return "invalid database version";
  case Errc::DatabaseError:
    return "database error";
  case Errc::RecordNotFound:
    return "database record not found";
  case Errc::DatabaseLocked:
    return "database locked";
  case Errc::DatabaseCorrupt:
    return "database corrupt";
  case Errc::DatabaseTooRecent:
    return "database too recent";
  case Errc::Last:
    break;
  }
  return "unknown error";
}

std::error_condition ErrcCategory::default_error_condition(int c) const noexcept
{
  switch (static_cast<Errc>(c))
  {
  case Errc::InvalidDatabaseVersion:
  case Errc::DatabaseError:
  case Errc::RecordNotFound:
  case Errc::DatabaseCorrupt:
    return make_error_condition(Errors::Errc::InternalError);
  case Errc::DatabaseLocked:
    return make_error_condition(Errors::Errc::PreconditionFailed);
  case Errc::DatabaseTooRecent:
    return make_error_condition(Errors::Errc::UpgradeRequired);
  case Errc::Last:
    break;
  }
  return std::error_condition(c, *this);
}
}
}
}
