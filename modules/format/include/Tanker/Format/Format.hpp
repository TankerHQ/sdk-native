#pragma once

#include <fmt/format.h>

#ifdef _MSC_VER
#define TFMT(s) s
#else
#define TFMT(s) FMT_STRING(s)
#endif
