cmake_minimum_required(VERSION 3.22.1)
project(iwscan C)

# Build the nl80211 scanner as an *executable*, but name it like a shared library (libiwscan.so)
# so the Android Gradle Plugin packages it into the APK's native lib dir, where it is executable.
add_executable(iwscan iwscan.c)

set_target_properties(iwscan PROPERTIES
    OUTPUT_NAME "iwscan"
    PREFIX "lib"
    SUFFIX ".so"
    # Emit into the dir AGP packages .so files from.
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}")

target_compile_options(iwscan PRIVATE -Wall -O2)
