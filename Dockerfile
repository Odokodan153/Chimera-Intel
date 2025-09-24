# --- Stage 1: The Builder ---
# Use a specific version for reproducibility
FROM python:3.11.9-slim-bullseye as builder

WORKDIR /app
# Install git, needed to clone the dnstwist repository
RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/elceef/dnstwist.git /app/dnstwist

# --- Stage 2: The Final Image ---
# Use the same specific version for the final image
FROM python:3.11.9-slim-bullseye

WORKDIR /app

# Install system dependencies required by the application and healthcheck
# nmap: for the vulnerability scanner
# curl: for the healthcheck
# geoip-database: for dnstwist
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    geoip-database \
    && rm -rf /var/lib/apt/lists/*

# Add a non-root user for better security
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# Copy the pre-built dnstwist tool from the builder stage
COPY --from=builder /app/dnstwist /app/dnstwist

# Optimize caching for dependencies by copying only the dependency file first
COPY pyproject.toml .
# Install all project dependencies defined in pyproject.toml
RUN pip install --no-cache-dir .
# Now, copy the rest of your application's source code
COPY . .
# Change the ownership of all files to the new non-root user
RUN chown -R appuser:appgroup /app

# Switch the context of the container to run as the new 'appuser'
USER appuser

# Set the environment PATH to include installed tools
ENV PATH="/home/appuser/.local/bin:/app/dnstwist:$PATH"

# Expose the port the web server will run on
EXPOSE 8000

# Add a healthcheck to ensure the application is running correctly
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8000/ || exit 1

# The command to run the web application using the Uvicorn production server
CMD ["uvicorn", "chimera_intel.webapp.main:app", "--host", "0.0.0.0", "--port", "8000"]