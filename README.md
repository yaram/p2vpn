# P2VPN
P2VPN is a work-in-progress Peer-to-Peer Virtual Private Network.

Windows is currently the only supported platform, but more are planned.

# Building

## Windows x64

Requirements:
* CMake 3.22.0 or later (This specific version is required because of a bug present in CMake version 3.21 and older that prevents building the vendored QT6 dependency)
* Ninja 1.10.0 or later
* Visual Studio 2019 with C++ build tools (MSVC)

Instructions:
1. Download or clone the repo into a directory
2. Open Visual Studio 2019 x64 Native Tools Command Prompt __OR__ run `vcvarsall.bat x64` in a command prompt to set up the MSVC environment variables
3. Create a directory for the build, and `cd` into it
4. Run `cmake -G Ninja -DCMAKE_BUILD_TYPE=Release {the source directory from step 1}`
5. Run `cmake --build . --target p2vpn --parallel`