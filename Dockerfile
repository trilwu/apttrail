FROM python:3.10-slim

WORKDIR /app

# Install git for repository updates
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Copy package definition
COPY pyproject.toml requirements.txt README.md ./
COPY src/ src/

# Install the package
RUN pip install --no-cache-dir .

# Create volume for data
VOLUME /app/data
VOLUME /app/feeds

# Default command
ENTRYPOINT ["apttrail"]
CMD ["--help"]
