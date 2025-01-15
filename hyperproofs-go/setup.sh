#!/bin/bash

cd mcl/
git checkout caf27db2 #herumi/mcl v1.86.0
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
sudo cmake --build build --target install
sudo ldconfig