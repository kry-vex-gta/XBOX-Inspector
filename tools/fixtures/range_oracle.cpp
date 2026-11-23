// Independent reference for union length on small synthetic fixtures.
#include <array>
#include <iostream>

int main() {
    std::array<bool, 4096> covered{};
    int first = 0;
    int past_last = 0;
    while (std::cin >> first >> past_last) {
        if (first < 0 || past_last < first || past_last > 4096) {
            return 2;
        }
        for (int i = first; i < past_last; ++i) {
            covered[static_cast<unsigned>(i)] = true;
        }
    }
    if (!std::cin.eof()) {
        return 2;
    }
    unsigned total = 0;
    for (const bool present : covered) {
        total += present;
    }
    std::cout << total << '\n';
}
