# P2VPN
P2VPN is a work-in-progress Peer-to-Peer Virtual Private Network.

Windows is currently the only supported platform, but more are planned.

# Building

## Windows x64

Requirements:
* CMake built from git commit [118a0adf](https://gitlab.kitware.com/cmake/cmake/-/tree/118a0adf5bf5a8629fd75da9d30f7e5c475eebbc) or later (This specific version is required because of a bug present in CMake version 3.21.2 and older that prevents building the vendored QT6 dependency)
* Ninja 1.10.0 or later
* Visual Studio 2019 with C++ build tools (MSVC)
* The latest amd64 `wintun.dll` from https://www.wintun.net

Instructions:
1. Download or clone the repo into a directory
2. Open Visual Studio 2019 x64 Native Tools Command Prompt __OR__ run `vcvarsall.bat x64` in a command prompt to set up the MSVC environment variables
3. Create a directory for the build, and `cd` into it
4. Run `cmake -G Ninja -DCMAKE_BUILD_TYPE=Release {the source directory from step 1}`
5. Run `cmake --build . --target p2vpn --parallel`
6. Copy the amd64 `wintun.dll` into the build folder alongside `p2vpn.exe`