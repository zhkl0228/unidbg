# [unicorn2](https://github.com/unicorn-engine/unicorn) backend

CMake build:<br>
` 0x0: git clone https://github.com/unicorn-engine/unicorn `<br>
` 0x1: cd unicorn && git checkout dev `<br>
` 0x2: mkdir build && cd build `<br>
` 0x3: cmake .. -DCMAKE_BUILD_TYPE=Release -DUNICORN_ARCH="arm aarch64" -DUNICORN_BUILD_SHARED=OFF `<br>
` 0x4: make -j8 `<br>
