#include <Tanker/Errors/Errc.hpp>

#include <string>

namespace Tanker
{
namespace Emscripten
{
struct EmError
{
  Errors::Errc code;
  std::string message;
};
}
}
