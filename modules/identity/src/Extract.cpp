#include <Tanker/Identity/Extract.hpp>

#include <cppcodec/base64_rfc4648.hpp>

namespace Tanker
{
namespace Identity
{
nlohmann::json extract(std::string const& token)
{
  return nlohmann::json::parse(cppcodec::base64_rfc4648::decode(token));
}
}
}
