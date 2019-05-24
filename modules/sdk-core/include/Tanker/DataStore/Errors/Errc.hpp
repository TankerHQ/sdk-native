#pragma once

#include <system_error>
#include <type_traits>

namespace Tanker
{
namespace DataStore
{
enum class Errc
{
  InvalidDatabaseVersion = 1,
  RecordNotFound,
  DatabaseError,
};

std::error_code make_error_code(Errc c) noexcept;
}
}

namespace std
{
template <>
struct is_error_code_enum<::Tanker::DataStore::Errc> : std::true_type
{
};
}
