# ClusterFuzzLite Dockerfile for device-fingerprinting
FROM gcr.io/oss-fuzz-base/base-builder-python

# Install system dependencies
RUN apt-get update && apt-get install -y \
    python3-dev \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . $SRC/device-fingerprinting
WORKDIR $SRC/device-fingerprinting

# Install Python dependencies
RUN pip3 install --upgrade pip && \
    pip3 install -r requirements.txt && \
    pip3 install atheris

# Install the package
RUN pip3 install -e .

# Copy build script
COPY .clusterfuzzlite/build.sh $SRC/
