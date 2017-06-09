cmake_minimum_required(VERSION 2.8)
project(Whitebox_crypto_AES)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x")
option(NTL_NO_DEFAULT_PATH "Using just given paths when searching for NTL" OFF)
option(BUILD_MAIN ON)
option(BUILD_DECRYPT_ONLY ON)

set(MAIN_SOURCE_FILES
    base.h
    base.cpp
    BGEAttack.cpp
    BGEAttack.h
    BGEAttack_test.cpp
    GenericAES.cpp
    GenericAES.h
    LinearAffineEq.cpp
    LinearAffineEq.h
    LinearAffineEq_test.cpp
    md5.c
    md5.h
    MixingBijections.cpp
    MixingBijections.h
    NTLUtils.cpp
    NTLUtils.h
    WBAES.cpp
    WBAES.h
    WBAESGenerator.cpp
    WBAESGenerator.h)

set(DECRYPT_ONLY_SOURCE_FILES
    decrypt-fn.cpp
    MixingBijections.cpp
    MixingBijections.h
    NTLUtils.cpp
    NTLUtils.h
    WBAES.cpp
    WBAES.h
    WBAESGenerator.cpp
    WBAESGenerator.h
    WBTables.h
)

if(BUILD_MAIN)
# NTL
  if (NTL_NO_DEFAULT_PATH)
    set(NTL_MODIF NO_DEFAULT_PATH)
    message("Not using default paths for NTL search, ${NTL_MODIF}")
  endif (NTL_NO_DEFAULT_PATH)
  message("HOME: $ENV{HOME}")
  find_path(NTL_INCLUDE_PATH NAMES NTL/mat_GF2.h PATHS $ENV{HOME}/ntl $ENV{HOME}/ntl/include /usr/local /opt/local /usr ${NTL_MODIF})
  message("NTL_INCLUDE_PATH: ${NTL_INCLUDE_PATH}")

  find_library(NTL_LIB ntl PATHS ${CMAKE_CURRENT_SOURCE_DIR} $ENV{HOME}/ntl $ENV{HOME}/ntl/lib /usr/local /opt/local /usr ${NTL_MODIF})
  if(NOT NTL_LIB)
      message(FATAL_ERROR "ntl library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
  endif()
  message("NTL_LIB: ${NTL_LIB}")
  include_directories(${NTL_INCLUDE_PATH})

  add_executable(main ${MAIN_SOURCE_FILES} main.cpp)
  add_executable(testing ${MAIN_SOURCE_FILES} testing.cpp testing.h)

  # BOOST
  set(Boost_USE_STATIC_LIBS OFF)
  set(Boost_USE_MULTITHREADED ON)
  set(Boost_USE_STATIC_RUNTIME OFF)
  find_package(Boost REQUIRED COMPONENTS program_options serialization iostreams random)
  include_directories(${Boost_INCLUDE_DIRS})

  set_target_properties(main PROPERTIES COMPILE_FLAGS "-DFULL_WBC_CODE_SUITE_WITH_DECRYPTION_TOO")
  set_target_properties(testing PROPERTIES COMPILE_FLAGS "-DFULL_WBC_CODE_SUITE_WITH_DECRYPTION_TOO")

  # Linking
  target_link_libraries(main ${NTL_LIB} "-lgmp" ${Boost_LIBRARIES})
  target_link_libraries(testing ${NTL_LIB} "-lgmp" ${Boost_LIBRARIES})
endif (BUILD_MAIN)

if (BUILD_DECRYPT_ONLY)
  add_executable(decrypt-only ${DECRYPT_ONLY_SOURCE_FILES} decrypt-only.cpp)
  set_target_properties(decrypt-only PROPERTIES COMPILE_FLAGS "")
  target_link_libraries(decrypt-only)
endif (BUILD_DECRYPT_ONLY)
