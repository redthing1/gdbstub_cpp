#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "gdbstub_tool/toy/types.hpp"

namespace gdbstub::toy {

struct reg_desc {
  std::string name;
  uint32_t bits = 0;
  uint32_t regno = 0;
  bool is_pc = false;
};

class layout {
public:
  explicit layout(const config& cfg) : pc_reg_num_(cfg.pc_reg_num), xml_arch_name_(cfg.xml_arch_name) {
    registers_.reserve(cfg.reg_count);
    for (size_t i = 0; i < cfg.reg_count; ++i) {
      reg_desc reg;
      reg.regno = static_cast<uint32_t>(i);
      reg.bits = cfg.reg_bits;
      reg.is_pc = static_cast<int>(i) == cfg.pc_reg_num;
      if (reg.is_pc) {
        reg.name = "pc";
      } else {
        reg.name = "r" + std::to_string(i);
      }
      registers_.push_back(std::move(reg));
    }
    target_xml_ = build_target_xml(cfg.architecture, cfg.xml_arch_name);
  }

  int reg_count() const { return static_cast<int>(registers_.size()); }
  int pc_reg_num() const { return pc_reg_num_; }

  size_t reg_size(int regno) const {
    if (regno < 0 || static_cast<size_t>(regno) >= registers_.size()) {
      return 0;
    }
    return registers_[static_cast<size_t>(regno)].bits / 8;
  }

  const std::string& xml_arch_name() const { return xml_arch_name_; }
  const std::string& target_xml() const { return target_xml_; }
  const std::vector<reg_desc>& registers() const { return registers_; }

private:
  std::string build_target_xml(std::string_view architecture, std::string_view feature_name) const {
    std::string xml;
    xml.reserve(256 + registers_.size() * 64);
    xml += "<target version=\"1.0\">";
    xml += "<architecture>";
    xml += architecture;
    xml += "</architecture>";
    xml += "<feature name=\"";
    xml += feature_name;
    xml += "\">";
    for (const auto& reg : registers_) {
      xml += "<reg name=\"";
      xml += reg.name;
      xml += "\" bitsize=\"";
      xml += std::to_string(reg.bits);
      xml += "\" regnum=\"";
      xml += std::to_string(reg.regno);
      xml += "\"";
      if (reg.is_pc) {
        xml += " type=\"code_ptr\"";
      }
      xml += "/>";
    }
    xml += "</feature></target>";
    return xml;
  }

  std::vector<reg_desc> registers_;
  int pc_reg_num_ = -1;
  std::string xml_arch_name_;
  std::string target_xml_;
};

} // namespace gdbstub::toy
