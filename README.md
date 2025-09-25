# CustodyCoach Backend

A Django REST Framework API backend for the CustodyCoach application with automatic OpenAPI/Swagger documentation.

## Features

- Django 5.0 with Django REST Framework
- Automatic OpenAPI 3.0 schema generation
- Interactive Swagger UI documentation
- ReDoc documentation interface
- Basic API endpoints for health checking and information

## Quick Start

### Prerequisites

- Python 3.8+
- pip

### Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd custodycoach-backend
```

2. Create and activate a virtual environment:
```bash
python3.11 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run migrations:
```bash
python manage.py migrate
```

5. Collect static files:
```bash
python manage.py collectstatic --noinput
```

6. Start the development server:
```bash
python manage.py runserver
```

## API Documentation

Once the server is running, you can access the API documentation at:

- **Swagger UI**: http://localhost:8000/api/docs/
- **ReDoc**: http://localhost:8000/api/redoc/
- **OpenAPI Schema**: http://localhost:8000/api/schema/

## API Endpoints

### Base URLs

- **API Root**: `GET /api/` - Welcome endpoint with API information
- **Health Check**: `GET /api/health/` - Service health status

### Admin Interface

- **Django Admin**: http://localhost:8000/admin/

## Project Structure

```
custodycoach-backend/
├── custodycoach/          # Django project settings
│   ├── __init__.py
│   ├── settings.py        # Main settings file
│   ├── urls.py           # URL configuration
│   └── wsgi.py
├── core/                 # Main application
│   ├── __init__.py
│   ├── views.py          # API views
│   └── urls.py           # App-specific URLs
├── manage.py             # Django management script
├── requirements.txt      # Python dependencies
└── README.md            # This file
```

## Development

### Running Tests

```bash
python manage.py test
```

### Creating a Superuser

```bash
python manage.py createsuperuser
```

### Adding New Apps

```bash
python manage.py startapp <app_name>
```

Don't forget to add the new app to `INSTALLED_APPS` in `settings.py`.

## Configuration

The project uses Django's default SQLite database for development. For production, update the `DATABASES` setting in `custodycoach/settings.py`.

### Environment Variables

While not currently implemented, it's recommended to use environment variables for sensitive settings like `SECRET_KEY` and database credentials in production.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

[Add your license information here]
