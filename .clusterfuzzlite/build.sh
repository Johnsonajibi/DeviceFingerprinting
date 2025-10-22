#!/bin/bash -eu
# ClusterFuzzLite build script for device-fingerprinting

# Navigate to project directory
cd $SRC/device-fingerprinting

# Install the package
pip3 install -e .

# Build fuzz targets
for fuzzer in fuzz/fuzz_*.py; do
  fuzzer_basename=$(basename -s .py $fuzzer)
  
  # Compile with atheris
  compile_python_fuzzer $fuzzer
done

# Copy seed corpus if available
if [ -d "fuzz/corpus" ]; then
  for fuzzer in fuzz/fuzz_*.py; do
    fuzzer_basename=$(basename -s .py $fuzzer)
    if [ -d "fuzz/corpus/${fuzzer_basename}" ]; then
      zip -j $OUT/${fuzzer_basename}_seed_corpus.zip fuzz/corpus/${fuzzer_basename}/* || true
    fi
  done
fi
