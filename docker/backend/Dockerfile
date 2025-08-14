FROM python:3.12-slim

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        build-essential \
        curl \
        wget \
        nginx \
        ca-certificates \
        npm && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip setuptools && \
    pip install --no-cache-dir -r requirements.txt
RUN pip install gunicorn==19.9.0

ADD ./backend /app/backend
ADD ./docker /app/docker
ADD ./models /app/models

RUN mkdir -p /app/backend/server/static