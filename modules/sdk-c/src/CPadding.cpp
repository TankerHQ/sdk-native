#include "CPadding.hpp"

#include <Tanker/Crypto/Padding.hpp>

std::optional<uint32_t> cPaddingToOptPadding(uint32_t padding_step)
{
  if (padding_step == Tanker::Padding::Auto)
    return std::nullopt;

  return padding_step;
}
