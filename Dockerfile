# --- Stage 1: The Builder ---
FROM python:3.11-slim as builder
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends git
RUN git clone https://github.com/elceef/dnstwist.git /app/dnstwist
COPY requirements.txt .
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --no-cache-dir -r requirements.txt

# --- Stage 2: The Final Image ---
FROM python:3.11-slim
WORKDIR /app
COPY --from=builder /opt/venv /opt/venv
COPY --from=builder /app/dnstwist /app/dnstwist

# CORRECTED: Copy the entire src directory
COPY src/ /app/src/

# CORRECTED: Install the package itself
RUN pip install /app/src/

ENV PATH="/opt/venv/bin:/app/dnstwist:$PATH"

# CORRECTED: Run the installed command-line script
ENTRYPOINT ["chimera"]
CMD ["--help"]