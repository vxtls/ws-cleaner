// Id generator proformence tester

#include <iostream>
#include <chrono>
#include "../SessionId.hpp"

int main() {
    constexpr int N = 1'000'000;

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < N; ++i) {
        std::string id = randomidgen::make_session_id();
        // no printing, std::cout is really slow
    }

    auto end = std::chrono::high_resolution_clock::now();

    double elapsed_sec = std::chrono::duration<double>(end - start).count();
    std::cout << "Generated " << N << " session IDs in "
              << elapsed_sec << " seconds.\n";
    std::cout << "Average speed: " << (N / elapsed_sec)
              << " IDs per second.\n";

    return 0;
}