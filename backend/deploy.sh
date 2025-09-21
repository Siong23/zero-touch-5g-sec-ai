#!/bin/bash
set -e

echo "Starting AEGIS-5G production deployment..."

# Create necessary directories
mkdir -p logs
mkdir -p staticfiles
mkdir -p media

# Install dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Collect static files
echo "Collecting static files..."
python manage.py collectstatic --noinput --settings=detection.production_settings

# Run database migrations
echo "Running database migrations..."
python manage.py migrate --settings=detection.production_settings

echo "Deployment completed successfully!"
echo ""
echo "To start the server:"
echo "1. Using Gunicorn:"
echo "   gunicorn --config gunicorn.conf.py detection.wsgi:application"
echo ""
echo "2. Using Daphne (ASGI):"
echo "   daphne -b 0.0.0.0 -p 8000 detection.asgi:application"
echo ""
echo "3. Using uWSGI:"
echo "   uwsgi --http :8000 --module detection.wsgi"