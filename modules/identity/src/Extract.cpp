#include <Tanker/Identity/Extract.hpp>

#include <cppcodec/base64_rfc4648.hpp>

namespace Tanker
{
namespace Identity
{
nlohmann::json extract(std::string const& token)
{
  try
  {
    return nlohmann::json::parse(cppcodec::base64_rfc4648::decode(token));
  }
  catch (nlohmann::json::exception const&)
  {
    throw std::invalid_argument(
        "Bad identity format - json deserialisation failed");
  }
  catch (cppcodec::parse_error const&)
  {
    throw std::invalid_argument(
        "Bad identity format - base64 deserialisation failed");
  }
  catch (std::invalid_argument const&)
  {
    throw std::invalid_argument(
        "cannot extract identity from provisional identity");
  }
}
}
}
