# P2VPN
P2VPN is a work-in-progress Peer-to-Peer Virtual Private Network.

Windows is currently the only supported platform, but more are planned.

# Building

## Windows x64

Requirements:
* CMake 3.21.2 or later
* Visual Studio 2019 with C++ build tools (MSVC)
* The latest amd64 `wintun.dll` from https://www.wintun.net

Instructions:
1. Download or clone the repo into a directory
2. Open Visual Studio 2019 x64 Native Tools Command Prompt __OR__ run `vcvarsall.bat x64` withing a command prompt to set up the MSVC environment variables
3. Create a directory for the build, and `cd` into it
4. Run `cmake -G Ninja -DCMAKE_BUILD_TYPE=Release {the source directory from step 1}`
5. Run `cmake --build . --target p2vpn --parallel`
6. Copy the amd64 `wintun.dll` into the build folder alongside `p2vpn.exe`