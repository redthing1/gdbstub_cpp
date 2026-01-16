#pragma once

#include <atomic>
#include <chrono>
#include <functional>
#include <mutex>
#include <optional>
#include <thread>

#include "gdbstub/rsp_types.hpp"
#include "gdbstub_tool/toy/machine.hpp"
#include "gdbstub_tool/toy/threads.hpp"
#include "gdbstub_tool/toy/types.hpp"

namespace gdbstub::toy {

class stop_tracker {
public:
  void set_callback(std::function<void(const stop_reason&)> callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    callback_ = std::move(callback);
  }

  void record_stop(const stop_reason& reason) {
    std::lock_guard<std::mutex> lock(mutex_);
    last_stop_ = reason;
  }

  void queue_stop(const stop_reason& reason) {
    std::function<void(const stop_reason&)> callback;
    bool notify = false;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      last_stop_ = reason;
      if (!pending_stop_) {
        pending_stop_ = reason;
        callback = callback_;
        notify = true;
      }
    }
    if (notify && callback) {
      callback(reason);
    }
  }

  std::optional<stop_reason> take_pending() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!pending_stop_) {
      return std::nullopt;
    }
    auto stop = pending_stop_;
    pending_stop_.reset();
    return stop;
  }

  std::optional<stop_reason> last_stop() {
    std::lock_guard<std::mutex> lock(mutex_);
    return last_stop_;
  }

private:
  std::mutex mutex_;
  std::optional<stop_reason> pending_stop_;
  std::optional<stop_reason> last_stop_;
  std::function<void(const stop_reason&)> callback_;
};

class runner {
public:
  runner(machine& machine, threads& threads, execution_mode mode, size_t max_steps)
      : machine_(machine), threads_(threads), mode_(mode), max_steps_(max_steps) {}

  ~runner() { stop_async(); }

  void set_mode(execution_mode mode) { mode_ = mode; }
  execution_mode mode() const { return mode_; }

  void set_max_steps(size_t max_steps) { max_steps_ = max_steps; }
  size_t max_steps() const { return max_steps_; }

  void set_async_callback(std::function<void(const stop_reason&)> callback) {
    stops_.set_callback(std::move(callback));
  }

  resume_result resume(const resume_request& request) {
    auto thread_id = threads_.current_thread();
    if (request.addr) {
      machine_.set_pc(*request.addr);
    }

    if (request.action == resume_action::step) {
      machine_.advance_pc();
      auto stop = machine_.signal_stop(thread_id);
      stops_.record_stop(stop);
      resume_result result;
      result.state = resume_result::state::stopped;
      result.stop = stop;
      return result;
    }

    if (auto stop = machine_.stop_if_breakpoint(thread_id)) {
      stops_.record_stop(*stop);
      resume_result result;
      result.state = resume_result::state::stopped;
      result.stop = *stop;
      return result;
    }

    if (mode_ == execution_mode::blocking) {
      auto stop = run_blocking(thread_id);
      stops_.record_stop(stop);
      resume_result result;
      result.state = resume_result::state::stopped;
      result.stop = stop;
      return result;
    }

    if (mode_ == execution_mode::polling) {
      running_.store(true);
      resume_result result;
      result.state = resume_result::state::running;
      return result;
    }

    if (mode_ == execution_mode::async) {
      start_async(thread_id);
      resume_result result;
      result.state = resume_result::state::running;
      return result;
    }

    auto stop = machine_.signal_stop(thread_id);
    stops_.record_stop(stop);
    resume_result result;
    result.state = resume_result::state::stopped;
    result.stop = stop;
    return result;
  }

  void interrupt() {
    stop_requested_.store(true);
    running_.store(false);
    stops_.queue_stop(machine_.signal_stop(threads_.current_thread()));
  }

  std::optional<stop_reason> poll_stop() {
    if (auto pending = stops_.take_pending()) {
      return pending;
    }

    if (mode_ != execution_mode::polling || !running_.load()) {
      return std::nullopt;
    }

    if (auto stop = machine_.step_and_check(threads_.current_thread())) {
      running_.store(false);
      stops_.record_stop(*stop);
      return stop;
    }

    return std::nullopt;
  }

  std::optional<stop_reason> last_stop() { return stops_.last_stop(); }

private:
  stop_reason run_blocking(uint64_t thread_id) {
    for (size_t i = 0; i < max_steps_; ++i) {
      if (auto stop = machine_.step_and_check(thread_id)) {
        return *stop;
      }
    }
    return machine_.signal_stop(thread_id);
  }

  void start_async(uint64_t thread_id) {
    stop_async();
    stop_requested_.store(false);
    running_.store(true);
    worker_ = std::thread([this, thread_id]() {
      for (size_t i = 0; i < max_steps_; ++i) {
        if (stop_requested_.load()) {
          stops_.queue_stop(machine_.signal_stop(thread_id));
          running_.store(false);
          return;
        }
        if (auto stop = machine_.step_and_check(thread_id)) {
          stops_.queue_stop(*stop);
          running_.store(false);
          return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
      }
      stops_.queue_stop(machine_.signal_stop(thread_id));
      running_.store(false);
    });
  }

  void stop_async() {
    stop_requested_.store(true);
    if (worker_.joinable()) {
      worker_.join();
    }
    running_.store(false);
  }

  machine& machine_;
  threads& threads_;
  execution_mode mode_ = execution_mode::blocking;
  size_t max_steps_ = 0;

  stop_tracker stops_;
  std::atomic<bool> running_{false};
  std::atomic<bool> stop_requested_{false};
  std::thread worker_;
};

} // namespace gdbstub::toy
