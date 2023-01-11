#pragma once

#include <catch2/reporters/catch_reporter_streaming_base.hpp>
#include <catch2/catch_test_case_info.hpp>
#include <catch2/reporters/catch_reporter_registrars.hpp>

#include <nlohmann/json.hpp>
#include <range/v3/range/conversion.hpp>
#include <range/v3/view/transform.hpp>

class TestNameReporter : public Catch::StreamingReporterBase {
public:
    using StreamingReporterBase::StreamingReporterBase;

    static std::string getDescription() {
        return "Reporter for formating test names in a JSON array";
    }

    void listTests(std::vector<Catch::TestCaseHandle> const& tests) override {
        auto testNames = tests |
             ranges::views::transform(&Catch::TestCaseHandle::getTestCaseInfo) |
             ranges::views::transform(&Catch::TestCaseInfo::name) |
             ranges::to<std::vector>;

        m_stream << nlohmann::json(testNames).dump();
    }
};

CATCH_REGISTER_REPORTER("test-names", TestNameReporter);
