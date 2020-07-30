find_package(PkgConfig REQUIRED)

find_package(Boost COMPONENTS program_options REQUIRED)

if (NOT Boost_FOUND)
    message(FATAL_ERROR "Boost library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
endif ()

find_library(NTL_LIB ntl PATHS "${ANDROID_NDK}/ntl/lib")
if (NOT NTL_LIB)
    message(FATAL_ERROR "ntl library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
endif ()

add_library(psi_analytics_eurocrypt19
        common/psi_analytics.cpp
        common/helpers.cpp
        polynomials/Mersenne.cpp
        polynomials/Poly.cpp
        ots/ots.cpp
        )
        
set_target_properties(psi_analytics_eurocrypt19
        PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        )

target_compile_options(psi_analytics_eurocrypt19
        PRIVATE
        -march=armv8-a+fp+simd+crypto+crc
        -ffunction-sections 
        -Wall -Wno-strict-overflow -Wno-ignored-attributes -Wno-parentheses)

target_link_libraries(psi_analytics_eurocrypt19 INTERFACE
        ABY::aby
        ENCRYPTO_utils::encrypto_utils
        GMP::GMP
        GMP::GMPXX
        ntl
        HashingTables
        libOTe
        Boost::program_options
        Threads::Threads
        # relic is a transitive dependency of libOTe right now
        # change relic to another library (if needed) if this changes
        relic_s
        )

target_include_directories(psi_analytics_eurocrypt19 PUBLIC
        ${PSI_ANALYTICS_SOURCE_ROOT}/psi_analytics_eurocrypt19
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/libOTe/cryptoTools
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/libOTe
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/ABY/src
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/ABY/extern/ENCRYPTO_utils/src
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/HashingTables
        ${PSI_ANALYTICS_SOURCE_ROOT}/extern/sse2neon/sse2neon.h
        ${ANDROID_NDK}/ntl/include
        ${ANDROID_NDK}/gmp/include
        ${ANDROID_NDK}/boost/include
        )

if (PSI_ANALYTICS_BUILD_EXAMPLE)
    add_executable(psi_analytics_eurocrypt19_example psi_analytics_example.cpp)

    target_link_libraries(psi_analytics_eurocrypt19_example PUBLIC
            psi_analytics_eurocrypt19
            )
    set_target_properties(psi_analytics_eurocrypt19_example
        PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
    )
endif (PSI_ANALYTICS_BUILD_EXAMPLE)
