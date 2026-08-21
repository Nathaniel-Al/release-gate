# syntax=docker/dockerfile:1

########################
# Stage 1: build deps  #
########################
FROM python:3.12-slim AS builder

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

########################
# Stage 2: runtime     #
########################
FROM python:3.12-slim

# Create a non-root user to run the app
RUN groupadd -r appuser && useradd -r -g appuser appuser

WORKDIR /app

# Bring in installed packages from the build stage only
COPY --from=builder /install /usr/local

COPY app.py .
COPY test ./test

# Render sets PORT at runtime; default it for local docker runs
ENV PORT=3000
EXPOSE 3000

USER appuser

CMD ["sh", "-c", "gunicorn --bind 0.0.0.0:${PORT} app:app"]
