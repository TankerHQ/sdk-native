#include <Tanker/Identity/Extract.hpp>

namespace Tanker
{
namespace Identity
{
nlohmann::json extract(std::string const& token)
{
  return nlohmann::json::parse(base64::decode(token));
}
}
}
