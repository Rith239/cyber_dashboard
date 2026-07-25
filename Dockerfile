# Use a slim, official Python base image
FROM python:3.13-slim

# Install Nmap (system package, not pip-installable) and other OS dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends nmap && \
    rm -rf /var/lib/apt/lists/*

# Set the working directory inside the container
WORKDIR /app

# Copy dependency list first (Docker caches this layer separately,
# so rebuilds are faster if only your code changes, not requirements.txt)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Render sets the PORT environment variable dynamically -- Waitress
# needs to bind to whatever port Render assigns, not a hardcoded one
ENV PORT=8000
EXPOSE 8000

# Start the app via Waitress (production WSGI server), reading the
# PORT Render provides at runtime
CMD waitress-serve --host=0.0.0.0 --port=$PORT run:app