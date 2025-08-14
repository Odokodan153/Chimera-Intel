# --- Stage 1: The Builder ---
FROM python:3.11-slim as builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git
RUN git clone https://github.com/elceef/dnstwist.git /app/dnstwist

# --- Stage 2: The Final Image ---
FROM python:3.11-slim
WORKDIR /app

# --- CHANGE 1: Add a non-root user for better security ---
# Create a new group 'appgroup' and a new user 'appuser' within that group.
# This prevents the container from running with root privileges.
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# Copy the pre-built dnstwist tool from the builder stage
COPY --from=builder /app/dnstwist /app/dnstwist

# --- CHANGE 2: Optimize caching for dependencies ---
# Copy only the dependency file first. This layer of the Docker image
# will only be rebuilt if you change your pyproject.toml file.
COPY pyproject.toml .

# Install all project dependencies defined in pyproject.toml.
# This step benefits from the caching optimization above.
RUN pip install .

# Now, copy the rest of your application's source code.
# This layer will be rebuilt on any code change, but the dependencies above won't be.
COPY . .

# --- Final Security Steps ---
# Change the ownership of all files in the /app directory to the new non-root user.
RUN chown -R appuser:appgroup /app

# Switch the context of the container to run as the new 'appuser'.
# All subsequent commands will be executed by this user.
USER appuser

# Set the environment PATH to include our installed tools so the OS can find them.
# We also add the user's local bin directory where pip installs command-line scripts.
ENV PATH="/home/appuser/.local/bin:/app/dnstwist:$PATH"

# Expose the port the web server will run on
EXPOSE 8000

# The command to run the web application using the Uvicorn production server.
CMD ["uvicorn", "chimera_intel.webapp.main:app", "--host", "0.0.0.0", "--port", "8000"]