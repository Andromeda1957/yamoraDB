#pragma once
#include "yamora/client.hpp"
#include <algorithm>
#include <cstdint>
#include <poll.h>

namespace yamora::detail {
struct Control {
    using Clock = std::chrono::steady_clock;
    Clock::time_point deadline;
    std::shared_ptr<const Cancellation> cancellation;
    void check() const {
        if (cancellation && cancellation->cancelled())
            throw Error(ErrorKind::cancelled, "yamora: operation cancelled");
        if (Clock::now() >= deadline)
            throw Error(ErrorKind::deadline, "yamora: operation deadline exceeded");
    }
    Control budget(std::chrono::milliseconds cap, std::size_t shares) const {
        check();
        auto now = Clock::now();
        return {std::min(deadline, now + std::min<Clock::duration>(cap, (deadline - now) / shares)),
                cancellation};
    }
    void pause(std::chrono::milliseconds delay) const {
        auto end = std::min(deadline, Clock::now() + delay);
        while (Clock::now() < end) {
            check();
            ::poll(nullptr, 0,
                   static_cast<int>(std::clamp<std::int64_t>(
                       std::chrono::ceil<std::chrono::milliseconds>(end - Clock::now()).count(), 0,
                       10)));
        }
        check();
    }
};
} // namespace yamora::detail
