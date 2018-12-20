#pragma once

#include <string>

namespace Tanker
{
struct UniquePath
{
  std::string path;

  explicit UniquePath(std::string const& dir);

  UniquePath(UniquePath const&) = delete;
  UniquePath& operator=(UniquePath const&) = delete;

  UniquePath(UniquePath&&) = default;
  UniquePath& operator=(UniquePath&&) = default;

  ~UniquePath();
};
}
