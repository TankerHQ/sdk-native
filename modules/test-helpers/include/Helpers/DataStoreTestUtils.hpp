#pragma once

#include <gsl/gsl-lite.hpp>

#include <string_view>
#include <utility>
#include <vector>

std::vector<std::pair<gsl::span<uint8_t const>, gsl::span<uint8_t const>>>
makeKeyValues(std::vector<std::pair<std::string_view, std::string_view>> vals);
std::vector<gsl::span<uint8_t const>> makeKeys(
    std::vector<std::string_view> keys);
