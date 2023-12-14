#include <Helpers/UniquePath.hpp>

#include <boost/filesystem.hpp>

#include <filesystem>

namespace Tanker
{
UniquePath::UniquePath(std::string const& dir) : path((dir / boost::filesystem::unique_path()).string())
{
  std::filesystem::create_directories(path);
}

UniquePath::~UniquePath()
{
  std::filesystem::remove_all(path);
}
}
