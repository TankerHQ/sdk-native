#pragma once

#include <boost/preprocessor/tuple/elem.hpp>

#define TANKER_DETAIL_ATTRIBUTE_NAME(elem) \
  BOOST_PP_CAT(_, BOOST_PP_TUPLE_ELEM(0, elem))

#define TANKER_DETAIL_TYPE_NAME(elem) BOOST_PP_TUPLE_ELEM(1, elem)
#define TANKER_DETAIL_PARAMETER_NAME(elem) BOOST_PP_TUPLE_ELEM(0, elem)

#define TANKER_DETAIL_FULL_PARAMETER(elem) \
  TANKER_DETAIL_TYPE_NAME(elem) const& TANKER_DETAIL_PARAMETER_NAME(elem)

#define TANKER_DETAIL_DEFINE_ATTRIBUTE(unused1, unused2, elem) \
  TANKER_DETAIL_TYPE_NAME(elem) TANKER_DETAIL_ATTRIBUTE_NAME(elem);

#define TANKER_DETAIL_DEFINE_GETTER(unused1, unused2, elem) \
  TANKER_DETAIL_FULL_PARAMETER(elem)() const                \
  {                                                         \
    return TANKER_DETAIL_ATTRIBUTE_NAME(elem);              \
  }
