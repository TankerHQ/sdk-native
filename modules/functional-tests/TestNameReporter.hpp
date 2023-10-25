#pragma once

#include <catch2/catch_test_case_info.hpp>
#include <catch2/reporters/catch_reporter_cumulative_base.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

#include <Tanker/Log/LogHandler.hpp>

#include <boost/algorithm/string.hpp>
#include <fmt/format.h>

#include <nlohmann/json.hpp>

namespace
{
struct Test
{
  std::string name;
  bool isLeaf;

  Test(std::string const& testName) : name{testName}, isLeaf{true}
  {
    boost::trim_right(name);
  }
};

void silentLogHandler(Tanker::Log::Record const&)
{
}
}

class TestNameReporter : public Catch::CumulativeReporterBase
{
public:
  using CumulativeReporterBase::CumulativeReporterBase;

  static std::string getDescription()
  {
    return "Reporter for formating test names in a JSON array";
  }

  void testRunStarting(Catch::TestRunInfo const& testRunInfo) override
  {
    CumulativeReporterBase::testRunStarting(testRunInfo);

    Tanker::Log::setLogHandler(&silentLogHandler);
  }

  void sectionStarting(Catch::SectionInfo const& sectionInfo) override
  {
    CumulativeReporterBase::sectionStarting(sectionInfo);

    stackTest(sectionInfo.name);
  }

  void sectionEnded(Catch::SectionStats const& sectionStats) override
  {
    CumulativeReporterBase::sectionEnded(sectionStats);

    auto const currentTest = _testStack.back();
    if (currentTest.isLeaf)
    {
      _testNames.emplace_back(currentTest.name);
    }

    _testStack.pop_back();
  }

  void testRunEndedCumulative() override
  {
    m_stream << nlohmann::json(_testNames).dump(2);
  };

private:
  void stackTest(std::string sectionName)
  {

    if (_testStack.empty())
    {
      _testStack.emplace_back(sectionName);
      return;
    }

    auto& lastSection = _testStack.back();
    lastSection.isLeaf = false;

    _testStack.emplace_back(
        fmt::format("{:s} {:s}", lastSection.name, sectionName));
  };

  std::vector<Test> _testStack{};
  std::vector<std::string> _testNames{};
};

CATCH_REGISTER_REPORTER("test-names", TestNameReporter)
