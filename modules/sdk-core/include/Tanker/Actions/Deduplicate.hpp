#pragma once

#include <range/v3/action/sort.hpp>
#include <range/v3/action/unique.hpp>

namespace Tanker::Actions
{
inline constexpr auto deduplicate =
    ranges::actions::sort | ranges::actions::unique;
}
