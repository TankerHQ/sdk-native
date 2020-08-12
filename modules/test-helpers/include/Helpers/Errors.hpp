#pragma once

#include <Tanker/Errors/Exception.hpp>

// with GCC10, system_error defines an operator<< for ostream, but it doesn't
// include ostream, which results in:
// /usr/bin/../lib/gcc/x86_64-linux-gnu/10/../../../../include/c++/10/system_error:263:20:
// error: invalid operands to binary expression ('basic_ostream<char,
// std::char_traits<char> >' and 'const char *')
#include <ostream>
#include <system_error>

#define TANKER_CHECK_THROWS_WITH_CODE(expr, code) \
  do                                              \
  {                                               \
    try                                           \
    {                                             \
      (void)(expr);                               \
      CHECK(false);                               \
    }                                             \
    catch (::Tanker::Errors::Exception const& e)  \
    {                                             \
      CHECK_EQ(e.errorCode(), code);              \
    }                                             \
  } while (0)

#define TANKER_CHECK_THROWS_WITH_CODE_AND_CONDITION(expr, code, condition) \
  do                                                                       \
  {                                                                        \
    try                                                                    \
    {                                                                      \
      (void)(expr);                                                        \
      CHECK(false);                                                        \
    }                                                                      \
    catch (::Tanker::Errors::Exception const& e)                           \
    {                                                                      \
      CHECK_EQ(e.errorCode(), code);                                       \
      CHECK_EQ(e.errorCondition(), condition);                             \
    }                                                                      \
  } while (0)
