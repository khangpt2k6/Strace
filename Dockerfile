FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    strace \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Install TraceGuard
RUN pip install --no-cache-dir -e .

# Create data directory
RUN mkdir -p /app/traceguard_data /app/traces

# Expose dashboard port
EXPOSE 5000

# Set entrypoint
ENTRYPOINT ["traceguard"]
CMD ["--help"]