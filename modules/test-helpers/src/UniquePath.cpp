#include <Helpers/UniquePath.hpp>

#include <fmt/format.h>

#include <boost/filesystem/operations.hpp>

namespace Tanker
{
#ifdef EMSCRIPTEN
UniquePath::UniquePath(std::string const& dir)
  : path(fmt::format("{}/{}", dir, rand()))
{
}

UniquePath::~UniquePath()
{
}
#else
UniquePath::UniquePath(std::string const& dir)
  : path((dir / boost::filesystem::unique_path()).c_str())
{
  boost::filesystem::create_directories(path);
}

UniquePath::~UniquePath()
{
  boost::filesystem::remove_all(path);
}
#endif
}
