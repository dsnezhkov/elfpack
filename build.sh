#!/bin/bash 
#cmake --build /home/dev/Code/elfpack/cmake-build-debug --target clean
#cmake --build /home/dev/Code/elfpack/cmake-build-debug --target all
cmake --config .
cmake --build . --target clean
cmake --build . --target all
