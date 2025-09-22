# Dockerfile for AEGIS-5G
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=detection.production_settings
ENV DEBIAN_FRONTEND=noninteractive

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    build-essential \
    libpq-dev \
    openssh-client \
    curl \
    procps \
    iputils-ping \
    net-tools \
    wget \
    vim \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Configure SSH client 
RUN mkdir -p /root/.ssh && \
    echo "Host *" >> /root/.ssh/config && \
    echo "    StrictHostKeyChecking no" >> /root/.ssh/config && \
    echo "    UserKnownHostsFile /dev/null" >> /root/.ssh/config && \
    echo "    ConnectTimeout 10" >> /root/.ssh/config && \
    echo "    ServerAliveInterval 5" >> /root/.ssh/config && \
    echo "    ServerAliveCountMax 3" >> /root/.ssh/config && \
    chmod 600 /root/.ssh/config

# Update pip
RUN pip install --upgrade pip

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .
COPY gunicorn.conf.py ./

# Create necessary directories
RUN mkdir -p logs staticfiles media

# Ensure model directory exists
RUN mkdir -p /app/app/model
RUN chmod -R 755 /app/app/model

# Collect static files
RUN python manage.py collectstatic --noinput

# Run migrations
RUN python manage.py migrate

# Expose port
EXPOSE 8000

# Command to run the application
CMD ["gunicorn", "--config", "gunicorn.conf.py", "detection.wsgi:application"]