#pragma once

#include <cstdint>
#include <mutex>
#include <vector>

#include "gdbstub/rsp_types.hpp"

namespace gdbstub::toy {

class threads {
public:
  explicit threads(std::vector<uint64_t> ids) : ids_(std::move(ids)) {
    if (ids_.empty()) {
      ids_.push_back(1);
    }
    current_thread_ = ids_.front();
  }

  std::vector<uint64_t> ids() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return ids_;
  }

  uint64_t current_thread() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return current_thread_;
  }

  target_status set_current_thread(uint64_t tid) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto id : ids_) {
      if (id == tid) {
        current_thread_ = tid;
        return target_status::ok;
      }
    }
    return target_status::invalid;
  }

private:
  mutable std::mutex mutex_;
  std::vector<uint64_t> ids_;
  uint64_t current_thread_ = 1;
};

} // namespace gdbstub::toy
