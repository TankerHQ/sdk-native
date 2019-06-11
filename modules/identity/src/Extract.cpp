#include <Tanker/Identity/Extract.hpp>

using namespace Tanker::Errors;

namespace Tanker
{
namespace Identity
{
namespace detail
{
nlohmann::json extract(std::string const& token)
{
  return nlohmann::json::parse(cppcodec::base64_rfc4648::decode(token));
}
}
}
}
