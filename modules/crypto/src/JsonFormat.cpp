#include <Tanker/Crypto/JsonFormat.hpp>

#include <nlohmann/json.hpp>

namespace Tanker
{
namespace Crypto
{
namespace detail
{
fmt::format_context::iterator format_json(nlohmann::json const& j,
                                          int width,
                                          fmt::format_context::iterator ctx)
{
  return fmt::format_to(ctx, "{:s}", j.dump(width));
}
}
}
}
