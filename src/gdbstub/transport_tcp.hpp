#pragma once

#include <chrono>
#include <cstddef>
#include <memory>
#include <span>
#include <string_view>

#include "gdbstub/transport.hpp"

namespace gdbstub {

class transport_tcp final : public transport {
public:
  transport_tcp();
  ~transport_tcp() override;

  transport_tcp(transport_tcp&&) noexcept;
  transport_tcp& operator=(transport_tcp&&) noexcept;

  transport_tcp(const transport_tcp&) = delete;
  transport_tcp& operator=(const transport_tcp&) = delete;

  bool listen(std::string_view address) override;
  bool accept() override;
  bool connected() const override;
  bool readable(std::chrono::milliseconds timeout) override;
  std::ptrdiff_t read(std::span<std::byte> out) override;
  std::ptrdiff_t write(std::span<const std::byte> data) override;
  void disconnect() override;
  void close() override;

private:
  class impl;
  std::unique_ptr<impl> impl_;
};

} // namespace gdbstub
