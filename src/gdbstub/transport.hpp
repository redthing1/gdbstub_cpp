#pragma once

#include <chrono>
#include <cstddef>
#include <span>
#include <string_view>

namespace gdbstub {

class transport {
public:
  virtual ~transport() = default;

  virtual bool listen(std::string_view address) = 0;
  virtual bool accept() = 0;
  virtual bool connected() const = 0;
  virtual bool readable(std::chrono::milliseconds timeout) = 0;
  virtual std::ptrdiff_t read(std::span<std::byte> out) = 0;
  virtual std::ptrdiff_t write(std::span<const std::byte> data) = 0;
  virtual void disconnect() = 0;
  virtual void close() = 0;
};

} // namespace gdbstub
