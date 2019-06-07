#include <Tanker/Identity/Extract.hpp>

#include <Tanker/Errors/Exception.hpp>
#include <Tanker/Identity/Errors/Errc.hpp>

#include <cppcodec/base64_rfc4648.hpp>

using namespace Tanker::Errors;

namespace Tanker
{
namespace Identity
{
namespace detail
{
nlohmann::json extract(std::string const& token)
{
  try
  {
    return nlohmann::json::parse(cppcodec::base64_rfc4648::decode(token));
  }
  catch (nlohmann::json::exception const&)
  {
    throw formatEx(Errc::InvalidFormat, "json deserialization failed");
  }
  catch (cppcodec::parse_error const&)
  {
    throw formatEx(Errc::InvalidFormat, "base64 deserialization failed");
  }
}
}
}
}
