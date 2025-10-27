#!/bin/bash -eu
# ClusterFuzzLite build script for device-fingerprinting

# Navigate to project directory
cd $SRC/device-fingerprinting

# Install Python dependencies first
pip3 install --upgrade pip setuptools wheel

# Install the package with dependencies
pip3 install -e . --no-cache-dir

# Verify installation
python3 -c "import device_fingerprinting; print('Package installed successfully')"

# Build fuzz targets
echo "Building fuzz targets from: $(pwd)/fuzz"
ls -la fuzz/

for fuzzer in $(pwd)/fuzz/fuzz_*.py; do
  if [ ! -f "$fuzzer" ]; then
    echo "Warning: Fuzzer file not found: $fuzzer"
    continue
  fi
  
  fuzzer_basename=$(basename -s .py $fuzzer)
  echo "Compiling fuzzer: $fuzzer_basename"
  
  # Compile with atheris - use full path
  compile_python_fuzzer "$fuzzer" --add-binary=/usr/local/lib/python3.*/dist-packages/atheris.so
  
  # Verify the fuzzer was created
  if [ -f "$OUT/$fuzzer_basename" ]; then
    echo "✓ Successfully created: $OUT/$fuzzer_basename"
    chmod +x "$OUT/$fuzzer_basename"
  else
    echo "✗ Failed to create: $OUT/$fuzzer_basename"
  fi
done

# List built fuzzers
echo "Built fuzzers in $OUT:"
ls -la $OUT/

# Copy seed corpus if available
if [ -d "fuzz/corpus" ]; then
  echo "Copying seed corpus..."
  for fuzzer in fuzz/fuzz_*.py; do
    fuzzer_basename=$(basename -s .py $fuzzer)
    if [ -d "fuzz/corpus/${fuzzer_basename}" ]; then
      echo "Creating corpus for: $fuzzer_basename"
      zip -j $OUT/${fuzzer_basename}_seed_corpus.zip fuzz/corpus/${fuzzer_basename}/* || true
    fi
  done
fi

echo "Build complete!"
