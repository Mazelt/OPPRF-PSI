# OPPRF-PSI for Android
This is the android port of the original OPPRF-PSI protocol implementation.
The non android related changes are also in
[original-opprf]{https://gitlab.informatik.hu-berlin.de/ti/theses/student-content/pazelt-marcel-ma/original-opprf}
The original readme is in section OPPRF-PSI below.

## Changes necessary for android.
Enable only SIMPLEST_OT disable ENABLE_SSE. 
Disable/Remove all x86 intrinsics, unless they can be
ported by means of [sse2neon]{https://github.com/DLTcollab/sse2neon} header
files. Use the ANDROID_STL:STRING=c++_shared.
## Dependencies
All dependencies were built against android using Android NDK. Changes to
CMakeLists.txt include variables that are pointing to android ports of
dependencies.

Check out notes in `Logbuch-BuildLibs` and `road-to-android.txt` for more
information.

Build the following (forked) projectrs against Android with NDK for your target ABI:

* Boost libaries
* GMP
* OpenSSL
* [ABY]{https://gitlab.informatik.hu-berlin.de/ti/theses/student-content/pazelt-marcel-ma/aby-android}
* [Encrypto_utils]{https://gitlab.informatik.hu-berlin.de/ti/theses/student-content/pazelt-marcel-ma/android-encrypto_utils}
* [libOTe]{https://gitlab.informatik.hu-berlin.de/ti/theses/student-content/pazelt-marcel-ma/android-libote}
* [NTL]{https://gitlab.informatik.hu-berlin.de/ti/theses/student-content/pazelt-marcel-ma/ntl-android} 
* [OTExtension]{https://gitlab.informatik.hu-berlin.de/ti/theses/student-content/pazelt-marcel-ma/android-otextension}
* [cryptoTools]{https://gitlab.informatik.hu-berlin.de/ti/theses/student-content/pazelt-marcel-ma/cryptotools}
* [HashingTables]{https://gitlab.informatik.hu-berlin.de/ti/theses/student-content/pazelt-marcel-ma/android-hashingtables}

Make sure the same SSE and intrinsics are disabled or ported for all dependencies.

## Build
To build, configure cmake to use Android NDK compilers for cross-compilation.
Configure all dependencies library dirs, ABI and SDK versions.

All changes to CMakeLists.txt are committed, but do point to local GMP, boost
and openssl binaries.

Configure cmake files and run the compilation as described below with the additional
parameters. Use the install dir parameter and cmake install command to place all
library output files in a desired directory to put them in the right place in
the AndroidStudioProject directory for the App building.

# OPPRF-PSI [![Build Status](https://travis-ci.org/encryptogroup/OPPRF-PSI.svg?branch=master)](https://travis-ci.org/encryptogroup/OPPRF-PSI)

An implementation of the first cirucit-based private set 
intersection protocol with linear communication complexity, which was presented at 
EUROCRYPT'19 \[[Pinkas-Schneider-Tkachenko-Yanai'19](https://ia.cr/2019/241)\].
Please note that this is not the same code that was benchmarked in the paper but a re-implementation.

## Required packages:
 - g++ (vection >=8) 
 - libboost-all-dev (version >=1.69) 
 - libgmp-dev 
 - libssl-dev 
 - libntl-dev

## Compilation

To compile as library.

```
mkdir build
cd build
cmake [OPTIONS] -DCMAKE_BUILD_TYPE=[Release|Debug] ..
make
// or make -j 10 for faster compilation
```

Available options are as follows:

- `-DPSI_ANALYTICS_BUILD_TESTS=ON` to compile tests
- `-DPSI_ANALYTICS_BUILD_EXAMPLE=ON` to compile an example with circuit-based threshold checking.

The options can be combined to build both the tests and the example.

## Tests

To run the tests and make sure that everything works as intended, 
you will need to run `cmake` with enabled `PSI_ANALYTICS_BUILD_TESTS`.
Then, run the test binary in `${build_directory}/bin/` without arguments.

## Applications

To run the available example, you will need to enable the `PSI_ANALYTICS_BUILD_EXAMPLE` flag.
Then, run the example binary in`${build_directory}/bin/` either from two terminals locally or 
between two machines.
To find information about the command line arguments, run `${example_name} --help`. 
Suitable parameters and formulas for calculating those can be found in the paper.
