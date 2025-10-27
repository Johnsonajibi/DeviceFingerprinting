#!/bin/bash -eu
# ClusterFuzzLite build script for device-fingerprinting

set -x  # Enable debug output

# Verify we're in the right place
echo "=== Build Script Started ==="
echo "Current directory: $(pwd)"
echo "SRC directory: $SRC"
echo "OUT directory: $OUT"

# Navigate to project directory
cd "$SRC/device-fingerprinting" || {
  echo "ERROR: Cannot find device-fingerprinting directory"
  ls -la "$SRC"
  exit 1
}

echo "=== Project Directory Contents ==="
ls -la

# Install Python dependencies first
echo "=== Installing Dependencies ==="
pip3 install --upgrade pip setuptools wheel
pip3 install atheris

# Install the package with dependencies
echo "=== Installing Package ==="
pip3 install -e . --no-cache-dir || {
  echo "ERROR: Package installation failed"
  exit 1
}

# Verify installation
echo "=== Verifying Installation ==="
python3 -c "import device_fingerprinting; print('✓ Package installed successfully')" || {
  echo "ERROR: Package verification failed"
  exit 1
}

# Check fuzz directory
echo "=== Checking Fuzz Directory ==="
if [ ! -d "fuzz" ]; then
  echo "ERROR: fuzz directory not found"
  exit 1
fi

ls -la fuzz/

# Build fuzz targets
echo "=== Building Fuzz Targets ==="
cd fuzz

for fuzzer_file in fuzz_*.py; do
  if [ ! -f "$fuzzer_file" ]; then
    echo "WARNING: Fuzzer file not found: $fuzzer_file"
    continue
  fi
  
  fuzzer_basename=$(basename -s .py "$fuzzer_file")
  echo "Processing: $fuzzer_basename"
  
  # Compile with atheris
  echo "Compiling: $fuzzer_file"
  compile_python_fuzzer "$(pwd)/$fuzzer_file" || {
    echo "ERROR: Failed to compile $fuzzer_file"
    exit 1
  }
  
  # Verify the fuzzer was created
  if [ -f "$OUT/$fuzzer_basename" ]; then
    echo "✓ Successfully created: $OUT/$fuzzer_basename"
    chmod +x "$OUT/$fuzzer_basename"
    ls -lh "$OUT/$fuzzer_basename"
  else
    echo "ERROR: Fuzzer not created: $OUT/$fuzzer_basename"
    echo "Contents of OUT directory:"
    ls -la "$OUT"
    exit 1
  fi
done

# List built fuzzers
echo "=== Built Fuzzers ==="
ls -lh "$OUT"

# Copy seed corpus if available
if [ -d "corpus" ]; then
  echo "=== Copying Seed Corpus ==="
  for fuzzer_file in fuzz_*.py; do
    fuzzer_basename=$(basename -s .py "$fuzzer_file")
    if [ -d "corpus/${fuzzer_basename}" ]; then
      echo "Creating corpus for: $fuzzer_basename"
      zip -j "$OUT/${fuzzer_basename}_seed_corpus.zip" corpus/${fuzzer_basename}/* || true
    fi
  done
fi

echo "=== Build Complete ==="
echo "Final fuzzer count: $(ls -1 $OUT/fuzz_* 2>/dev/null | wc -l)"
