#include <Tanker/Format/Json.hpp>

#include <fmt/core.h>
#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Format
{
namespace detail
{
fmt::format_context::iterator formatJson(nlohmann::json const& j, int width, fmt::format_context::iterator ctx)
{
  return fmt::format_to(ctx, "{:s}", j.dump(width));
}
}
}
}
