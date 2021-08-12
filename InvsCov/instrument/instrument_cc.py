#!/usr/bin/env python3

import subprocess
import sys
import os

be_quite = os.getenv("INVSCOV_QUIET") is not None

invscov_outpath = os.getenv("INVSCOV_OUTPUT_PATH")
if invscov_outpath is None:
    invscov_outpath = "invscov_output"
    if not be_quite:
        print("WARN: INVSCOV_OUTPUT_PATH env not set, fallback to default 'invscov_output'")

script_dir = os.path.dirname(os.path.realpath(os.path.abspath(__file__)))

is_cxx = "++" in sys.argv[0]

aflpp_path = os.path.join(script_dir, "..", "..", "AFLplusplus")
if os.getenv("AFLPP_PATH"):
    aflpp_path = os.getenv("AFLPP_PATH")

def cc_exec(args):
    if os.getenv("INVSCOV_CC"):
        cc_name = os.environ["INVSCOV_CC"]
    else:
        cc_name = "clang-10"
    if is_cxx:
        if os.getenv("INVSCOV_CXX"):
            cc_name = os.environ["INVSCOV_CXX"]
        else:
            cc_name = "clang++-10"
    argv = [cc_name] + args
    #print(" ".join(argv))
    return subprocess.run(argv)


def common_opts():
    return [
      "-g",
      #"-fno-inline",
      #"-fno-unroll-loops",
      #"-O0",
      "-fno-discard-value-names",
    ]

def cc_mode():
    args = common_opts()
    args += sys.argv[1:]
    
    if not os.getenv("NO_CONSTRS"):
        args += [
          "-Xclang", "-load", "-Xclang", os.path.join(script_dir, "instrument_pass.so"),
        ]

    if os.getenv("LAF_INTEL"):
        args += [
          "-Xclang", "-load", "-Xclang", os.path.join(aflpp_path, "split-switches-pass.so"),
          "-Xclang", "-load", "-Xclang", os.path.join(aflpp_path, "compare-transform-pass.so"),
          "-Xclang", "-load", "-Xclang", os.path.join(aflpp_path, "split-compares-pass.so"),
        ]
    if os.getenv("CMPLOG"):
        args += [
          "-Xclang", "-load", "-Xclang", os.path.join(aflpp_path, "cmplog-routines-pass.so"),
          "-Xclang", "-load", "-Xclang", os.path.join(aflpp_path, "split-switches-pass.so"),
          "-Xclang", "-load", "-Xclang", os.path.join(aflpp_path, "cmplog-instructions-pass.so"),
        ]

    args += [
      "-Xclang", "-load", "-Xclang", os.path.join(aflpp_path, "afl-llvm-pass.so")
    ]
    
    if os.getenv("AFL_USE_ASAN"):
        args += ["-fsanitize=address"]
    if os.getenv("AFL_USE_MSAN"):
        args += ["-fsanitize=memory"]
    if os.getenv("AFL_USE_UBSAN"):
        args += [
                  "-fsanitize=undefined",
                  "-fsanitize-undefined-trap-on-error",
                  "-fno-sanitize-recover=all",
                ]

    return cc_exec(args)

def ld_mode():
    args = common_opts()
    
    args += sys.argv[1:]
    if not os.getenv("NO_CONSTRS"):
        args += [os.path.join(invscov_outpath, "constraints.o")]
    args += [os.path.join(aflpp_path, "afl-llvm-rt.o")]

    if not os.getenv("NO_CONSTRS"):
        args += [
          "-Xclang", "-load", "-Xclang", os.path.join(script_dir, "instrument_pass.so"),
        ]

    if os.getenv("LAF_INTEL"):
        args += [
          "-Xclang", "-load", "-Xclang", os.path.join(aflpp_path, "split-switches-pass.so"),
          "-Xclang", "-load", "-Xclang", os.path.join(aflpp_path, "compare-transform-pass.so"),
          "-Xclang", "-load", "-Xclang", os.path.join(aflpp_path, "split-compares-pass.so"),
        ]
    if os.getenv("CMPLOG"):
        args += [
          "-Xclang", "-load", "-Xclang", os.path.join(aflpp_path, "cmplog-routines-pass.so"),
          "-Xclang", "-load", "-Xclang", os.path.join(aflpp_path, "split-switches-pass.so"),
          "-Xclang", "-load", "-Xclang", os.path.join(aflpp_path, "cmplog-instructions-pass.so"),
        ]

    args += [
      "-Xclang", "-load", "-Xclang", os.path.join(aflpp_path, "afl-llvm-pass.so")
    ]
    
    args += ["-lstdc++"]
    #args += ["-std=c++14"]
    
    if os.getenv("AFL_USE_ASAN"):
        args += ["-fsanitize=address"]
    if os.getenv("AFL_USE_MSAN"):
        args += ["-fsanitize=memory"]
    if os.getenv("AFL_USE_UBSAN"):
        args += [
                  "-fsanitize=undefined",
                  "-fsanitize-undefined-trap-on-error",
                  "-fno-sanitize-recover=all",
                ]
    
    return cc_exec(args)

def is_ld_mode():
    return not ("--version" in sys.argv or "--target-help" in sys.argv or
                "-c" in sys.argv or "-E" in sys.argv or "-S" in sys.argv or
                "-shared" in sys.argv)

if not be_quite:
    print("\x1b[0;36m" + os.path.basename(sys.argv[0]) + " 1.0a\x1b[0m by <andreafioraldi@gmail.com>")

if len(sys.argv) <= 1:
  cc_exec(sys.argv[1:])
elif is_ld_mode():
    ld_mode()
else:
    cc_mode()
