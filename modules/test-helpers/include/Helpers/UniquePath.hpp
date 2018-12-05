#pragma once

#include <boost/filesystem/path.hpp>

namespace Tanker
{
struct UniquePath
{
  boost::filesystem::path path;

  explicit UniquePath(boost::filesystem::path const& dir);

  UniquePath(UniquePath const&) = delete;
  UniquePath& operator=(UniquePath const&) = delete;

  UniquePath(UniquePath&&) = default;
  UniquePath& operator=(UniquePath&&) = default;

  ~UniquePath();
};
}
