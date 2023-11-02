# OPPRF-PSI for Android
This is the android port of the original OPPRF-PSI protocol implementation.
It was used for the paper [Circuit-based PSI for Covid-19 Risk Scoring](https://www.computer.org/csdl/proceedings-article/ipccc/2021/09679360/1AjTpCJji6c) by Reichert, Pazelt and Scheuermann [PDF](https://eprint.iacr.org/2021/1475).

It still contains a bunch of notes for myself that were created duing the build/implementation process.
Some links still link to the gitlab I used, but the submodules were changed to link to the original github repositories.

The original readme is in section OPPRF-PSI below.

## Changes necessary for android.
Enable only SIMPLEST_OT disable ENABLE_SSE. 
Disable/Remove all x86 intrinsics, unless they can be
ported by means of [sse2neon](https://github.com/DLTcollab/sse2neon) header
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
* ABY
* Encrypto_utils
* libOTe
* NTL
* OTExtension
* cryptoTools
* HashingTables

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
