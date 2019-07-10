#pragma once

#include <Tanker/Errors/Exception.hpp>

#include <system_error>

#define TANKER_CHECK_THROWS_WITH_CODE(expr, code) \
  do                                              \
  {                                               \
    try                                           \
    {                                             \
      expr;                                       \
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
      expr;                                                                \
      CHECK(false);                                                        \
    }                                                                      \
    catch (::Tanker::Errors::Exception const& e)                           \
    {                                                                      \
      CHECK_EQ(e.errorCode(), code);                                       \
      CHECK_EQ(e.errorCondition(), condition);                             \
    }                                                                      \
  } while (0)
