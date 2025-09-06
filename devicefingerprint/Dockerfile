# Use Python 3.11 slim image for smaller size
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies if needed
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Install the library from PyPI
RUN pip install device-fingerprinting-pro

# Copy example scripts
COPY examples/ /app/examples/
COPY README.md /app/

# Create a demo script
RUN echo '#!/usr/bin/env python3\n\
from devicefingerprint import generate_device_fingerprint, AdvancedDeviceFingerprinter, FingerprintMethod\n\
import json\n\
\n\
print("=== DeviceFingerprint Demo ===")\n\
print("\\nBasic fingerprint:")\n\
basic_fp = generate_device_fingerprint()\n\
print(f"  {basic_fp}")\n\
\n\
print("\\nAdvanced fingerprinting:")\n\
fingerprinter = AdvancedDeviceFingerprinter()\n\
result = fingerprinter.generate_fingerprint(FingerprintMethod.QUANTUM_RESISTANT)\n\
print(f"  Fingerprint: {result.fingerprint}")\n\
print(f"  Confidence: {result.confidence}")\n\
print(f"  Method: {result.method.value}")\n\
print(f"  Components: {len(result.components)}")\n\
\n\
print("\\n=== Demo Complete ===")\n\
' > /app/demo.py && chmod +x /app/demo.py

# Set the default command
CMD ["python", "/app/demo.py"]

# Labels for Docker Hub
LABEL maintainer="johnson@devicefingerprint.dev" \
      version="1.0.3" \
      description="DeviceFingerprint - Professional hardware-based device identification" \
      org.opencontainers.image.source="https://github.com/Johnsonajibi/DeviceFingerprinting" \
      org.opencontainers.image.documentation="https://github.com/Johnsonajibi/DeviceFingerprinting#readme" \
      org.opencontainers.image.licenses="MIT"
