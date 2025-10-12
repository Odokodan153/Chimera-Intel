# Stage 1: Build the application
FROM python:3.9-slim as builder

WORKDIR /app

# Install build dependencies
COPY pyproject.toml .
RUN pip install --upgrade pip && pip install .

# Copy the rest of the application code
COPY . .

# Stage 2: Final production image
FROM python:3.9-slim

WORKDIR /app

# Copy the installed packages from the builder stage
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=builder /app .

# Set environment variables for production
# These would be populated by your container orchestration system (e.g., Kubernetes, Docker Compose)
ENV VAULT_ADDR="https://your-vault-server.com"
ENV VAULT_TOKEN="your-vault-access-token"
ENV VAULT_SECRET_PATH="kv/data/chimera-intel"
ENV DB_HOST="your-postgres-host"
ENV DB_USER="your-db-user"
ENV DB_PASSWORD="your-db-password"
ENV DB_NAME="chimera_intel"
ENV LOG_LEVEL="INFO"

# Run the application as a non-root user for enhanced security
RUN useradd --create-home appuser
USER appuser

# Expose the port the web application runs on
EXPOSE 8000

# The command to run the web application
CMD ["uvicorn", "webapp.main:app", "--host", "0.0.0.0", "--port", "8000"]