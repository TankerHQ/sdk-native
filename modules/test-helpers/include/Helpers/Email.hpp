#pragma once

#include <Tanker/Types/Email.hpp>

namespace Tanker
{
auto makeEmail(std::string_view name = "bob",
               std::string_view domain = "tanker.io") -> Email;
}
