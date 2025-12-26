// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <cstdio>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/flags/usage.h"
#include "absl/log/check.h"
#include "absl/log/initialize.h"
#include "absl/log/log.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "tests/verilator_sim/coralnpu/core_mini_axi_tb.h"
#include "tests/verilator_sim/sysc_tb.h"

/* clang-format off */
#include <systemc.h>
/* clang-format on */

ABSL_FLAG(int, cycles, 100000000, "Simulation cycles");
ABSL_FLAG(bool, trace, false, "Dump VCD trace");
ABSL_FLAG(std::string, binary, "", "Binary to execute");
ABSL_FLAG(bool, debug_axi, false, "Enable AXI traffic debugging");
ABSL_FLAG(bool, instr_trace, false, "Log instructions to console");
ABSL_FLAG(std::string, dump_mem, "",
          "Dump memory after halt (format: addr:size:file, e.g., 0x10080:128:output.bin)");

// Memory dump configuration
struct MemDumpConfig {
  bool enabled = false;
  uint32_t addr = 0;
  uint32_t size = 0;
  std::string file;
};

static MemDumpConfig ParseDumpMemFlag(const std::string& flag) {
  MemDumpConfig config;
  if (flag.empty()) return config;

  std::vector<std::string> parts = absl::StrSplit(flag, ':');
  if (parts.size() != 3) {
    LOG(ERROR) << "Invalid --dump_mem format. Expected addr:size:file (e.g., 0x10080:128:output.bin)";
    return config;
  }

  // Parse hex address
  if (parts[0].substr(0, 2) == "0x" || parts[0].substr(0, 2) == "0X") {
    config.addr = std::stoul(parts[0], nullptr, 16);
  } else {
    config.addr = std::stoul(parts[0], nullptr, 10);
  }

  // Parse size
  if (!absl::SimpleAtoi(parts[1], &config.size)) {
    LOG(ERROR) << "Invalid size in --dump_mem: " << parts[1];
    return config;
  }

  config.file = parts[2];
  config.enabled = true;
  LOG(INFO) << "Memory dump configured: addr=0x" << std::hex << config.addr
            << " size=" << std::dec << config.size << " file=" << config.file;
  return config;
}

static bool run(const char* name, const std::string binary, const int cycles,
                const bool trace, const bool debug_axi, const bool instr_trace,
                const MemDumpConfig& dump_config) {
  absl::Mutex halted_mtx;
  absl::CondVar halted_cv;
  CoreMiniAxi_tb tb(CoreMiniAxi_tb::kCoreMiniAxiModelName, cycles, /* random= */ false, debug_axi,
                    instr_trace,
                    /*wfi_cb=*/std::nullopt,
                    /*halted_cb=*/[&halted_mtx, &halted_cv]() {
                      absl::MutexLock lock_(&halted_mtx);
                      halted_cv.SignalAll();
                    });
  if (trace) {
    tb.trace(tb.core());
  }

  std::thread sc_main_thread([&tb]() { tb.start(); });

  CHECK_OK(tb.LoadElfSync(binary));
  CHECK_OK(tb.ClockGateSync(false));
  CHECK_OK(tb.ResetAsync(false));

  {
    absl::MutexLock lock_(&halted_mtx);
    halted_cv.Wait(&halted_mtx);
  }

  if (!tb.io_fault && !tb.tohost_halt) {
    CHECK_OK(tb.CheckStatusSync());
  }

  // Read memory dump via AXI before stopping simulation
  std::vector<uint8_t> mem_data;
  if (dump_config.enabled) {
    LOG(INFO) << "Reading memory at 0x" << std::hex << dump_config.addr
              << " (" << std::dec << dump_config.size << " bytes)...";
    mem_data = tb.ReadMemorySync(dump_config.addr, dump_config.size);
  }

  sc_stop();
  sc_main_thread.join();

  // Write memory dump to file (after simulation stopped)
  if (dump_config.enabled && !mem_data.empty()) {
    FILE* f = fopen(dump_config.file.c_str(), "wb");
    if (f) {
      size_t written = fwrite(mem_data.data(), 1, mem_data.size(), f);
      fclose(f);
      LOG(INFO) << "Memory dump written to: " << dump_config.file
                << " (" << written << " bytes)";
    } else {
      LOG(ERROR) << "Failed to open dump file: " << dump_config.file;
    }
  }

  return (!tb.io_fault && !(tb.tohost_halt && tb.tohost_val != 1));
}

extern "C" int sc_main(int argc, char** argv) {
  absl::InitializeLog();
  absl::SetProgramUsageMessage("CoreMiniAxi simulator");
  auto args = absl::ParseCommandLine(argc, argv);
  argc = args.size();
  argv = &args[0];

  if (absl::GetFlag(FLAGS_binary) == "") {
    LOG(ERROR) << "--binary is required!";
    return -1;
  }

  MemDumpConfig dump_config = ParseDumpMemFlag(absl::GetFlag(FLAGS_dump_mem));

  return run(Sysc_tb::get_name(argv[0]), absl::GetFlag(FLAGS_binary),
      absl::GetFlag(FLAGS_cycles), absl::GetFlag(FLAGS_trace),
      absl::GetFlag(FLAGS_debug_axi), absl::GetFlag(FLAGS_instr_trace),
      dump_config) ? 0 : 1;
}
