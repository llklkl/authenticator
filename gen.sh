#!/bin/bash

flutter_rust_bridge_codegen.exe \
    --rust-input ./src/api.rs \
    --dart-output ./flutter/lib/ffi/bridge_gen.dart \
    --llvm-path $LLVM_PATH
