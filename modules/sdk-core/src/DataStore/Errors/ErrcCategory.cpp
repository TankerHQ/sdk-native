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
  case Errc::DatabaseLocked:
  case Errc::DatabaseCorrupt:
    return make_error_condition(Errors::Errc::InternalError);
  }
  return std::error_condition(c, *this);
}
}
}
}
