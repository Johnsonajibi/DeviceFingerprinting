# ClusterFuzzLite Dockerfile for device-fingerprinting
FROM gcr.io/oss-fuzz-base/base-builder-python

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3-dev \
    python3-pip \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip and install atheris
RUN pip3 install --upgrade pip setuptools wheel && \
    pip3 install atheris

# Copy project files
COPY . $SRC/device-fingerprinting
WORKDIR $SRC/device-fingerprinting

# Install Python dependencies (but not the package yet - build.sh will do that)
RUN if [ -f requirements.txt ]; then \
      pip3 install -r requirements.txt --no-cache-dir; \
    fi

# Copy build script
COPY .clusterfuzzlite/build.sh $SRC/build.sh
RUN chmod +x $SRC/build.sh
