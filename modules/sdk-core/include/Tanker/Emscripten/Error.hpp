#include <Tanker/Error.hpp>

#include <string>

namespace Tanker
{
namespace Emscripten
{
struct EmError
{
  Error::Code code;
  std::string message;
};
}
}
