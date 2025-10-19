# Fuzzing Tests for Device Fingerprinting Pro

This directory contains fuzz tests for security testing using [Atheris](https://github.com/google/atheris).

## Fuzz Targets

### 1. `fuzz_crypto.py`
Tests cryptographic operations:
- AES-GCM encryption/decryption with malformed data
- SHA3-512 hashing with edge cases  
- Scrypt key derivation with invalid parameters
- Tampered ciphertext handling

### 2. `fuzz_fingerprint.py`
Tests fingerprint generation:
- Hardware data parsing
- JSON serialization edge cases
- Hash collision handling
- Corrupted fingerprint data

### 3. `fuzz_storage.py`
Tests secure storage:
- File I/O with corrupt data
- Key-value operations with invalid keys
- Encryption key management
- Storage corruption recovery

## Running Locally

### Install Atheris

```bash
pip install atheris
```

### Run Individual Fuzzers

```bash
# Run crypto fuzzer for 5 minutes
python fuzz/fuzz_crypto.py -max_total_time=300

# Run fingerprint fuzzer
python fuzz/fuzz_fingerprint.py -max_total_time=300

# Run storage fuzzer
python fuzz/fuzz_storage.py -max_total_time=300
```

### Run with Specific Input

```bash
# Test with a specific crash file
python fuzz/fuzz_crypto.py crash-1234567890
```

### Common Options

```bash
# Run for 10 minutes
python fuzz/fuzz_crypto.py -max_total_time=600

# Limit iterations
python fuzz/fuzz_crypto.py -runs=10000

# Increase verbosity
python fuzz/fuzz_crypto.py -verbosity=2

# Use seed corpus
mkdir -p fuzz/corpus/fuzz_crypto
python fuzz/fuzz_crypto.py fuzz/corpus/fuzz_crypto
```

## Understanding Output

```
INFO: Seed: 1234567890
INFO: -max_len is not provided; libFuzzer will guess a good value
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED cov: 123 ft: 456 corp: 1/1b exec/s: 0 rss: 45Mb
#1000   NEW    cov: 234 ft: 789 corp: 2/10b lim: 4 exec/s: 500 rss: 46Mb
#10000  NEW    cov: 345 ft: 1012 corp: 5/25b lim: 8 exec/s: 1000 rss: 48Mb
```

- **cov**: Code coverage (higher is better)
- **ft**: Features discovered
- **corp**: Corpus size (interesting inputs found)
- **exec/s**: Executions per second
- **rss**: Memory usage

## Crashes

When a crash is found:

1. **Crash file created**: `crash-<hash>`
2. **Reproduce**: `python fuzz/fuzz_crypto.py crash-<hash>`
3. **Debug**: Add print statements or use debugger
4. **Fix**: Patch the bug
5. **Verify**: Run fuzzer again to confirm fix

## Continuous Fuzzing

Fuzzing runs automatically:
- On every push to `main`
- On every pull request
- Daily at 2 AM UTC (scheduled)

Results available in GitHub Actions.

## Creating Seed Corpus

Seed corpus helps fuzzing find bugs faster:

```bash
# Create corpus directories
mkdir -p fuzz/corpus/fuzz_crypto
mkdir -p fuzz/corpus/fuzz_fingerprint
mkdir -p fuzz/corpus/fuzz_storage

# Add example inputs
echo "test_password_123" > fuzz/corpus/fuzz_crypto/password1.txt
echo "another_test" > fuzz/corpus/fuzz_crypto/password2.txt
echo '{"cpu":"Intel"}' > fuzz/corpus/fuzz_fingerprint/hardware1.json
```

## Advanced Usage

### Dictionary Files

Create word lists for better mutations:

```bash
# fuzz/fuzz_crypto.dict
"AES-GCM"
"SHA3-512"
"Scrypt"
"password"
"\x00\x00\x00\x00"
```

Use with:
```bash
python fuzz/fuzz_crypto.py -dict=fuzz/fuzz_crypto.dict
```

### Coverage Reports

```bash
# Generate coverage
python fuzz/fuzz_crypto.py -max_total_time=60 -print_coverage=1
```

### Multiple Fuzzing Engines

```bash
# Use AFL (requires afl-fuzz)
afl-fuzz -i corpus -o findings python fuzz/fuzz_crypto.py @@

# Use Honggfuzz (requires honggfuzz)
honggfuzz -i corpus -o findings -- python fuzz/fuzz_crypto.py
```

## Troubleshooting

### ModuleNotFoundError

```bash
# Install in editable mode
pip install -e .
```

### Atheris Not Found

```bash
pip install atheris
```

### Slow Fuzzing

- Reduce `-max_total_time`
- Use fewer iterations
- Add seed corpus
- Run on faster hardware

## Resources

- **Atheris Documentation**: https://github.com/google/atheris
- **Fuzzing Guide**: https://google.github.io/oss-fuzz/
- **libFuzzer Options**: https://llvm.org/docs/LibFuzzer.html

## Security

If you find a security vulnerability through fuzzing:

1. **DO NOT** open a public issue
2. Email: info@devicefingerprinting.dev
3. Include crash file and reproduction steps
4. We will respond within 48 hours

## Contributing

To add new fuzz targets:

1. Create `fuzz/fuzz_newmodule.py`
2. Follow existing fuzzer structure
3. Add to CI workflow (`.github/workflows/fuzzing.yml`)
4. Update this README
5. Submit pull request

## License

Same as main project (MIT License)
