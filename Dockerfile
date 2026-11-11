# Quantum Guard (PS07) — Portable Docker Environment
# Uses Alpine 3.22 which ships native OpenSSL 3.5.x (with FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA)
FROM python:3.11-alpine3.22

WORKDIR /app

# Install OpenSSL 3.5+ CLI and runtime libraries
RUN apk add --no-cache \
    openssl \
    ca-certificates \
    bash \
    && openssl version

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source and test suite
COPY app/ ./app/
COPY scripts/ ./scripts/
COPY tests/ ./tests/
COPY README.md .

# Ensure data directory exists with appropriate permissions
RUN mkdir -p /app/data && chmod 700 /app/data

# Expose FastAPI dashboard port (8000) and simulated enterprise TLS ports (9441-9445)
EXPOSE 8000 9441 9442 9443 9444 9445

ENV OPENSSL_BIN=/usr/bin/openssl
ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
