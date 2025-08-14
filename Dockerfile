# --- Stage 1: The Builder ---
# This stage installs system-level dependencies.
FROM python:3.11-slim as builder
WORKDIR /app
# Install git, which is needed to clone the dnstwist repository.
RUN apt-get update && apt-get install -y --no-install-recommends git
# Clone the dnstwist tool into a directory in our builder.
RUN git clone https://github.com/elceef/dnstwist.git /app/dnstwist

# --- Stage 2: The Final Image ---
# Start fresh with a clean Python image for our application.
FROM python:3.11-slim
WORKDIR /app

# Copy the pre-built dnstwist tool from the builder stage.
COPY --from=builder /app/dnstwist /app/dnstwist

# Copy the ENTIRE project context (src/, pyproject.toml, etc.) into the container.
COPY . .
# Install the project using pip. This command reads pyproject.toml,
# installs all Python dependencies, and sets up the 'chimera' command.
RUN pip install .

# Set the environment PATH to include our installed tools so the OS can find them.
ENV PATH="/usr/local/bin:/app/dnstwist:$PATH"

# Expose the port the web server will run on
EXPOSE 8000

# The command to run the web application using the Uvicorn production server.
# This will be the default action when the container starts.
CMD ["uvicorn", "chimera_intel.webapp.main:app", "--host", "0.0.0.0", "--port", "8000"]