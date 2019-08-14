#pragma once

#include <tconcurrent/coroutine.hpp>

#include <chrono>
#include <functional>
#include <vector>

namespace Tanker
{
namespace FileKit
{
using DelayList = std::vector<std::chrono::milliseconds>;

DelayList exponentialDelays(int retries);
tc::cotask<void> retry(std::function<tc::cotask<void>()> f,
                       DelayList const& delays);
}
}
