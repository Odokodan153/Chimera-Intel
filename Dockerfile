# --- Stage 1: The Builder ---
# We start with a full Python image to get all the build tools we need.
FROM python:3.11-slim as builder

# Set the working directory inside the container
WORKDIR /app

# Install system-level dependencies. We need 'git' to clone dnstwist.
RUN apt-get update && apt-get install -y --no-install-recommends git

# Clone the dnstwist repository, as it's a critical system dependency
RUN git clone https://github.com/elceef/dnstwist.git /app/dnstwist
# Make it executable from anywhere by adding it to the PATH
ENV PATH="/app/dnstwist:${PATH}"

# Install Python dependencies into a dedicated virtual environment
COPY requirements.txt .
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir -r requirements.txt

# --- Stage 2: The Final Image ---
# We start from a clean, slim Python image for our final application.
FROM python:3.11-slim

# Set the working directory
WORKDIR /app

# Copy the virtual environment with all installed Python libraries from the builder stage
COPY --from=builder /opt/venv /opt/venv

# Copy the dnstwist tool from the builder stage
COPY --from=builder /app/dnstwist /app/dnstwist

# Copy our application's source code into the container
COPY modules/ /app/modules/
COPY main.py .

# Set the environment PATH to include our venv and dnstwist
ENV PATH="/opt/venv/bin:/app/dnstwist:$PATH"

# Set the entry point. This is the command that will run when the container starts.
# It's equivalent to running 'python main.py' from the terminal.
ENTRYPOINT ["python", "main.py"]

# Set the default command to show the help message if no other command is provided.
CMD ["--help"]