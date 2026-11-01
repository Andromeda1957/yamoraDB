// Fault injection at the actual JSON decoder dependency. No source inspection
// or alternate SDK implementation: network, routing and recovery run normally.
#include "../src/json.hpp"
#include <atomic>
#include <cstdlib>
#include <new>
#include <thread>

namespace {
std::atomic<bool> allocation_failure{false};
std::shared_ptr<yamora::Cancellation> cancellation;
} // namespace
void fault_cancellation(std::shared_ptr<yamora::Cancellation> value) {
    cancellation = std::move(value);
}
void fault_reset() noexcept { allocation_failure.store(false); }
void *operator new(std::size_t count) {
    if (allocation_failure.load())
        throw std::bad_alloc();
    if (auto p = std::malloc(count ? count : 1))
        return p;
    throw std::bad_alloc();
}
void *operator new[](std::size_t count) { return ::operator new(count); }
void operator delete(void *p) noexcept { std::free(p); }
void operator delete[](void *p) noexcept { std::free(p); }
void operator delete(void *p, std::size_t) noexcept { std::free(p); }
void operator delete[](void *p, std::size_t) noexcept { std::free(p); }

namespace yamora::detail {
Json real_decode(std::string_view, const Control &) asm(
    "__real__ZN6yamora6detail6decodeESt17basic_string_viewIcSt11char_"
    "traitsIcEERKNS0_7ControlE");
Json wrap_decode(std::string_view, const Control &) asm(
    "__wrap__ZN6yamora6detail6decodeESt17basic_string_viewIcSt11char_"
    "traitsIcEERKNS0_7ControlE");
Json wrap_decode(std::string_view input, const Control &control) {
    auto value = real_decode(input, control);
    const char *setting = std::getenv("CPP_DECODE_FAULT");
    if (!setting || input.find("validation-fault") == input.npos)
        return value;
    std::string_view mode(setting);
    if (mode == "cancel")
        cancellation->cancel();
    if (mode == "deadline")
        std::this_thread::sleep_until(control.deadline + std::chrono::milliseconds(2));
    if (mode == "concurrent-allocation")
        throw std::bad_alloc();
    if (mode == "allocation") {
        allocation_failure.store(true);
        throw std::bad_alloc();
    }
    return value;
}
} // namespace yamora::detail
