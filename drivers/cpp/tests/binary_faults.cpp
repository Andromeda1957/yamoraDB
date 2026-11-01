// Linker-only observation/fault injection; no production test switches.
#include "../src/binary_wire.hpp"
#include <atomic>
#include <cstdlib>
#include <new>
#include <thread>

std::atomic<unsigned> binary_large_freezes{0};
std::atomic<bool> binary_fail_allocations{false};
std::atomic<unsigned> binary_failed_allocations{0};
void *operator new(std::size_t count) {
  if (binary_fail_allocations.load()) {
    ++binary_failed_allocations;
    throw std::bad_alloc();
  }
  if (auto p = std::malloc(count ? count : 1))
    return p;
  throw std::bad_alloc();
}
void *operator new[](std::size_t count) { return ::operator new(count); }
void operator delete(void *p) noexcept { std::free(p); }
void operator delete[](void *p) noexcept { std::free(p); }
void operator delete(void *p, std::size_t) noexcept { std::free(p); }
void operator delete[](void *p, std::size_t) noexcept { std::free(p); }
using namespace yamora;
using namespace yamora::binary_detail;
std::string real_freeze(std::string_view, const detail::Control &) asm(
    "__real__ZN6yamora13binary_detail6freezeB5cxx11ESt17basic_string_"
    "viewIcSt11char_traitsIcEERKNS_6detail7ControlE");
std::string wrapped_freeze(std::string_view, const detail::Control &) asm(
    "__wrap__ZN6yamora13binary_detail6freezeB5cxx11ESt17basic_string_"
    "viewIcSt11char_traitsIcEERKNS_6detail7ControlE");
std::string wrapped_freeze(std::string_view source,
                           const detail::Control &control) {
  if (source.size() == max_document_bytes)
    ++binary_large_freezes;
  return real_freeze(source, control);
}
void real_semantics(
    const Reply &, BinaryMethod, std::string_view, std::string_view,
    std::string_view,
    const detail::Control
        &) asm("__real__ZN6yamora13binary_detail9semanticsERKNS0_5ReplyENS_"
               "12BinaryMethodESt17basic_string_viewIcSt11char_traitsIcEES8_S8_"
               "RKNS_6detail7ControlE");
void wrapped_semantics(
    const Reply &, BinaryMethod, std::string_view, std::string_view,
    std::string_view,
    const detail::Control
        &) asm("__wrap__ZN6yamora13binary_detail9semanticsERKNS0_5ReplyENS_"
               "12BinaryMethodESt17basic_string_viewIcSt11char_traitsIcEES8_S8_"
               "RKNS_6detail7ControlE");
void wrapped_semantics(const Reply &r, BinaryMethod method,
                       std::string_view collection, std::string_view document,
                       std::string_view source,
                       const detail::Control &control) {
  // The complete peer receipt proves dispatch. The actual JSON map allocation
  // now fails, and every subsequent operator new remains failed until the
  // caller catches the propagated result outside BinaryClient.
  if (const char *mode = std::getenv("B_HOLD_ALLOC_FAILURE")) {
    if (std::string_view(mode) == "error") {
      Error owned(ErrorKind::protocol, "test: preowned semantic failure");
      binary_fail_allocations.store(true);
      try {
        // Actual rejected allocation followed by an already-owned Error tests
        // the other after-dispatch handler while the allocator stays failed.
        auto memory = ::operator new(64);
        ::operator delete(memory);
      } catch (const std::bad_alloc &) {
        throw owned;
      }
    }
    binary_fail_allocations.store(true);
  }
  real_semantics(r, method, collection, document, source, control);
  if (std::getenv("B_FINAL_CANCEL"))
    const_cast<Cancellation *>(control.cancellation.get())->cancel();
  if (std::getenv("B_FINAL_DEADLINE"))
    std::this_thread::sleep_until(control.deadline +
                                  std::chrono::milliseconds(1));
}
