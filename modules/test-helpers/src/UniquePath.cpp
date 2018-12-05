#include <Helpers/UniquePath.hpp>

#include <boost/filesystem/operations.hpp>

namespace Tanker
{
UniquePath::UniquePath(boost::filesystem::path const& dir)
  : path(dir / boost::filesystem::unique_path())
{
  boost::filesystem::create_directories(path);
}

UniquePath::~UniquePath()
{
  boost::filesystem::remove_all(path);
}
}
