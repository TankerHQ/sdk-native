#pragma once

#include <boost/algorithm/string/join.hpp>

#include <catch2/reporters/catch_reporter_cumulative_base.hpp>
#include <catch2/catch_test_case_info.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

#include <nlohmann/json.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

class TestNameReporter : public Catch::CumulativeReporterBase {
public:
    using CumulativeReporterBase::CumulativeReporterBase;

    static std::string getDescription() {
        return "Reporter for formating test names in a JSON array";
    }

    void testCaseStarting(Catch::TestCaseInfo const& testInfo) override {
        CumulativeReporterBase::testCaseStarting(testInfo);

        _testStack.emplace_back(testInfo.name);
    };

    void testCaseEnded(Catch::TestCaseStats const& testCaseStats) override {
        CumulativeReporterBase::testCaseEnded(testCaseStats);

        if (!_testStack.empty()) {
            _testStack.pop_back();
        }
    }

    void sectionStarting(Catch::SectionInfo const& sectionInfo) override {
        CumulativeReporterBase::sectionStarting(sectionInfo);

        _testStack.emplace_back(sectionInfo.name);
        _testNames.emplace_back(boost::algorithm::join(_testStack, " "));
        _testStack.pop_back();
    }

    void testRunEndedCumulative() override {
        m_stream << nlohmann::json(_testNames).dump();
    };

private:
    std::vector<std::string> _testStack{};
    std::vector<std::string> _testNames{};
};

CATCH_REGISTER_REPORTER("test-names", TestNameReporter);
