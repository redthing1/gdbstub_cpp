#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>
#include <thread>

#include "gdbstub/server.hpp"
#include "gdbstub/tcp_test_client.hpp"
#include "gdbstub/transport_tcp.hpp"
#include "gdbstub_tool/toy/target.hpp"

namespace gdbstub::test {

class toy_session {
public:
  explicit toy_session(gdbstub::toy::config cfg) : mode_(cfg.mode), target_(std::move(cfg)) {
    auto transport = std::make_unique<gdbstub::transport_tcp>();
    server_ = std::make_unique<gdbstub::server>(target_.make_target(), target_.make_arch_spec(), std::move(transport));
  }

  toy_session(const toy_session&) = delete;
  toy_session& operator=(const toy_session&) = delete;

  ~toy_session() { shutdown(); }

  bool listen_and_connect(std::string_view host, uint16_t base_port, uint16_t max_attempts) {
    if (!server_) {
      return false;
    }

    port_ = gdbstub::test::listen_on_available_port(*server_, host, base_port, max_attempts);
    if (!port_) {
      return false;
    }

    accepted_.store(false);
    accept_thread_ = std::thread([this]() {
      if (server_) {
        accepted_.store(server_->wait_for_connection());
      }
    });

    bool connected = client_.connect(host, *port_);
    if (accept_thread_.joinable()) {
      accept_thread_.join();
    }
    if (!connected || !accepted_.load()) {
      shutdown();
      return false;
    }
    return true;
  }

  void shutdown() {
    client_.close();
    if (server_) {
      server_->stop();
    }
    if (accept_thread_.joinable()) {
      accept_thread_.join();
    }
  }

  gdbstub::server& server() { return *server_; }
  gdbstub::test::tcp_client& client() { return client_; }
  gdbstub::toy::target& target() { return target_; }
  std::optional<uint16_t> port() const { return port_; }
  gdbstub::toy::execution_mode mode() const { return mode_; }

private:
  gdbstub::toy::execution_mode mode_ = gdbstub::toy::execution_mode::blocking;
  gdbstub::toy::target target_;
  std::unique_ptr<gdbstub::server> server_;
  gdbstub::test::tcp_client client_;
  std::optional<uint16_t> port_;
  std::atomic<bool> accepted_{false};
  std::thread accept_thread_;
};

} // namespace gdbstub::test
