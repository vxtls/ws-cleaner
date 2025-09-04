#pragma once
#include <random>
#include <atomic>
#include <chrono>
#include <string>
#include <cstdio>

namespace randomidgen {
static std::atomic<uint64_t> g_session_counter{0};
inline std::mt19937_64& get_tls_rng() {
    thread_local std::mt19937_64 tls_rng([]{
        std::random_device rd;
        return std::mt19937_64(rd());
    }());
    return tls_rng;
}

inline std::string make_session_id() {
    uint64_t a = std::uniform_int_distribution<uint64_t>{}(get_tls_rng());
    uint64_t b = std::uniform_int_distribution<uint64_t>{}(get_tls_rng());
    uint64_t cnt = g_session_counter.fetch_add(1, std::memory_order_relaxed);

    auto now = std::chrono::steady_clock::now();
    uint64_t ns = std::chrono::duration_cast<std::chrono::nanoseconds>(now.time_since_epoch()).count();

    char buf[16+16+16+8+1]; // 56 hex chars + null terminator
    std::snprintf(buf, sizeof(buf), "%016lx%016lx%016lx%08lx", a, b, ns, cnt);

    return std::string(buf);
}

} // namespace randomidgen
