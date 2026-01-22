# Flask Auth Skeleton Dockerfile
# Requirements: 8.1 - THE System SHALL include a Dockerfile that builds the Flask application

# Use Python 3.11 slim base image for smaller image size
FROM python:3.11-slim

# Set environment variables
# Prevents Python from writing pyc files to disc
ENV PYTHONDONTWRITEBYTECODE=1
# Prevents Python from buffering stdout and stderr
ENV PYTHONUNBUFFERED=1

# Set the working directory in the container
WORKDIR /app

# Install system dependencies required for bcrypt and other packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements file first for better Docker layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code
COPY . .

# Create data directory for SQLite database
RUN mkdir -p /data

# Create a non-root user for security
RUN useradd --create-home --shell /bin/bash appuser && \
    chown -R appuser:appuser /app && \
    chown -R appuser:appuser /data
USER appuser

# Expose the Flask default port
EXPOSE 5000

# Set the default command to run the Flask application with Gunicorn
# Using Gunicorn for production-ready serving
# The run:app refers to the app object in run.py (created in Task 15.2)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "run:app"]
