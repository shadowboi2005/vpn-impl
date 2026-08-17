#pragma once

#include <cstdio>
#include <cstdlib>
#include <span>
#include <string>
#include <string_view>

// A test runner small enough to read in one sitting. PLAN.md says to ask before
// adding dependencies, and a framework is not worth asking for when the whole
// need is "report which case failed and exit nonzero".

namespace vpn::test {

inline int failures = 0;
inline int checks = 0;
inline std::string current_case;

inline void begin(std::string_view name) {
    current_case = name;
}

inline void fail(const char* file, int line, const std::string& what) {
    ++failures;
    std::fprintf(stderr, "\033[31mFAIL\033[0m %s:%d\n  case: %s\n  %s\n", file, line,
                 current_case.c_str(), what.c_str());
}

inline void check(bool condition, const char* expression, const char* file, int line) {
    ++checks;
    if (!condition) {
        fail(file, line, std::string("expected: ") + expression);
    }
}

template <typename A, typename B>
void check_eq(const A& actual, const B& expected, const char* expression, const char* file,
              int line) {
    ++checks;
    if (!(actual == expected)) {
        fail(file, line, std::string(expression) + "\n  actual:   " + std::to_string(actual) +
                             "\n  expected: " + std::to_string(expected));
    }
}

inline bool same_bytes(std::span<const uint8_t> a, std::span<const uint8_t> b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

inline int report(const char* suite) {
    if (failures == 0) {
        std::printf("\033[32mPASS\033[0m %s — %d checks\n", suite, checks);
        return 0;
    }
    std::printf("\033[31mFAIL\033[0m %s — %d of %d checks failed\n", suite, failures, checks);
    return 1;
}

}  // namespace vpn::test

#define CHECK(cond) ::vpn::test::check((cond), #cond, __FILE__, __LINE__)
#define CHECK_EQ(a, b) ::vpn::test::check_eq((a), (b), #a " == " #b, __FILE__, __LINE__)
#define CASE(name) ::vpn::test::begin(name)
