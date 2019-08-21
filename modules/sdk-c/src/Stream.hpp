#pragma once

#include <Tanker/StreamInputSource.hpp>
#include <Tanker/Types/SResourceId.hpp>
#include <Tanker/task_canceler.hpp>

struct tanker_stream
{
  Tanker::StreamInputSource inputSource;
  Tanker::SResourceId resourceId;
  Tanker::task_canceler canceler;
};
