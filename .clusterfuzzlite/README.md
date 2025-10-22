# ClusterFuzzLite Configuration

This directory contains the ClusterFuzzLite configuration for continuous fuzzing of the device-fingerprinting library.

## What is ClusterFuzzLite?

ClusterFuzzLite brings advanced fuzzing capabilities (from Google's OSS-Fuzz) to your own CI/CD pipeline. It runs directly in GitHub Actions, providing:

- ✅ **Same fuzzing engines as OSS-Fuzz** (LibFuzzer, AFL++)
- ✅ **Multiple sanitizers** (AddressSanitizer, UndefinedBehaviorSanitizer)
- ✅ **Automatic crash detection and reporting**
- ✅ **PR integration** - Fuzzes pull requests before merge
- ✅ **No external dependencies** - Runs on your infrastructure

## Files

### `project.yaml`
Configuration file specifying:
- Project metadata (homepage, contact)
- Language (Python)
- Sanitizers to use (address, undefined)
- Fuzzing engines (libfuzzer, afl)

### `Dockerfile`
Docker container configuration that:
- Sets up the fuzzing environment
- Installs dependencies
- Prepares the project for fuzzing

### `build.sh`
Build script that:
- Installs the device_fingerprinting package
- Compiles fuzz targets with instrumentation
- Prepares corpus data if available

## Fuzz Targets

ClusterFuzzLite will run these fuzz targets:

1. **fuzz_crypto.py** - Tests cryptographic operations
   - Encryption/decryption with random data
   - Hash operations with malformed inputs
   - Key derivation edge cases
   - Corrupted ciphertext handling

2. **fuzz_fingerprint.py** - Tests device fingerprinting
   - Fingerprint generation with various inputs
   - Malformed hardware data handling
   - JSON serialization edge cases

3. **fuzz_storage.py** - Tests secure storage
   - Set/get operations with random data
   - Invalid key handling
   - Delete operations on non-existent items
   - Concurrent access patterns

## Workflow Schedule

The ClusterFuzzLite workflow runs:
- **On every PR** - 5 minutes of fuzzing per target (quick feedback)
- **On push to main** - 30 minutes of fuzzing per sanitizer (thorough testing)
- **Twice daily (scheduled)** - 2 AM and 2 PM UTC (continuous monitoring)

## How It Works

### Pull Requests
1. Code is pushed to a PR
2. Fuzzers are built with instrumentation
3. Each fuzzer runs for 5 minutes
4. If crashes are found:
   - Artifacts are uploaded
   - SARIF results are sent to GitHub Security
   - PR checks fail to prevent merge

### Main Branch / Scheduled
1. Longer fuzzing sessions (30 minutes per sanitizer)
2. Results stored in `gh-pages` branch
3. Corpus is grown over time
4. Historical crash data maintained

## Viewing Results

### In Pull Requests
- Check the PR checks status
- Review SARIF findings in "Security" → "Code scanning alerts"
- Download crash artifacts from workflow runs

### After Merge
- View workflow runs in Actions tab
- Download artifacts for detailed analysis
- Check GITHUB_STEP_SUMMARY for quick overview

## Reproducing Crashes Locally

If ClusterFuzzLite finds a crash:

1. Download the crash artifact from the workflow run
2. Extract the crash file
3. Run locally:
   ```bash
   python fuzz/fuzz_<target>.py <path_to_crash_file>
   ```
4. Debug with your preferred tools
5. Fix the issue
6. Verify fix:
   ```bash
   python fuzz/fuzz_<target>.py -max_total_time=60
   ```

## Storage

ClusterFuzzLite uses the `gh-pages` branch to store:
- Corpus data (interesting inputs discovered)
- Historical crash information
- Coverage data

This allows fuzzing to improve over time by building on previous discoveries.

## Resources

- [ClusterFuzzLite Documentation](https://google.github.io/clusterfuzzlite/)
- [GitHub Action](https://github.com/google/clusterfuzzlite)
- [Atheris (Python Fuzzer)](https://github.com/google/atheris)

## Migrating to OSS-Fuzz Later

When the project gains wider adoption, you can:
1. Submit to OSS-Fuzz again
2. Use the same Dockerfile, build.sh, and fuzz targets
3. Transfer corpus data from gh-pages branch
4. Continue fuzzing with more resources

ClusterFuzzLite is an excellent stepping stone to full OSS-Fuzz integration!
