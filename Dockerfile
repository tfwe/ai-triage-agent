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
COPY . .

# Build the evidence corpus inside the image: no network, no model, deterministic
RUN python -m eval.corpus_build

# Ensure the non-root user owns the files
RUN chown -R agentuser:agentuser /app

# Switch to the non-root user
USER agentuser

# Checks (and pulls, if needed) the Ollama model from config.py's settings
# before handing off to CMD below
ENTRYPOINT ["python", "docker-entrypoint.py"]

# By default, replay the recorded eval run: no model and no network required
CMD ["python", "-m", "eval.run_evals", "--mode", "replay"]

