#pragma once

#ifdef __GNUC__
#define TANKER_MAYBE_UNUSED __attribute__((unused))
#else
#define TANKER_MAYBE_UNUSED
#endif

#ifdef __GNUC__
#define TANKER_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#elif defined(_MSC_VER)
#define TANKER_WARN_UNUSED_RESULT _Check_return_
#endif
