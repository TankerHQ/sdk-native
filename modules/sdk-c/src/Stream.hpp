#pragma once

#include <Tanker/Streams/InputSource.hpp>
#include <Tanker/Types/SResourceId.hpp>
#include <Tanker/task_canceler.hpp>

struct tanker_stream
{
  Tanker::Streams::InputSource inputSource;
  Tanker::SResourceId resourceId;
  Tanker::task_canceler canceler;
};
