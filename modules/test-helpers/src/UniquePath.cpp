#include <Helpers/UniquePath.hpp>

#include <boost/filesystem/operations.hpp>

namespace Tanker
{
UniquePath::UniquePath(std::string const& dir)
  : path((dir / boost::filesystem::unique_path()).string())
{
  boost::filesystem::create_directories(path);
}

UniquePath::~UniquePath()
{
  boost::filesystem::remove_all(path);
}
}
