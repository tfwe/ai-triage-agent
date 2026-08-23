# Use a lightweight Python base image
FROM python:3.11-slim

# Prevent Python from writing .pyc files and buffer stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Create a non-root user for security
RUN useradd -m -r agentuser

WORKDIR /app

# Install dependencies first to cache the layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY data/ ./data/
COPY parsers/ ./parsers/
COPY agent/ ./agent/
COPY eval/ ./eval/
COPY . . 

# Ensure the non-root user owns the files
RUN chown -R agentuser:agentuser /app

# Switch to the non-root user
USER agentuser

# By default, run the evaluation harness to prove the system works
CMD ["python", "-m", "eval.run_evals"]
