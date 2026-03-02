# Build a local LLDB

- git clone https://github.com/llvm/llvm-project
- cd llvm-project
- mkdir build/; cd build/
- sudo apt install libedit-dev ninja
- `cmake -S ../llvm -DLLVM_ENABLE_PROJECTS="clang;lldb" -B . -G Ninja`
- ninja -j32
- ln -s `pwd`/bin/lldb ~/.local/bin/

# Build this component

- `cargo build --release --target wasm32-wasip2`

# Run Wasmtime with debug component

- `../wasmtime/target/debug/wasmtime run -D debugger=target/wasm32-wasip2/release/gdbstub_component.wasm -Ddebugger-arg=0.0.0.0:1234 ./test.wasm`

# Attach LLDB

- `lldb` (make sure it's the build from above)
  - at its prompt: `process connect --plugin wasm connect://localhost:1234`

