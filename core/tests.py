from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status


class APIEndpointsTest(APITestCase):
    """Test cases for the core API endpoints."""

    def test_api_root(self):
        """Test the API root endpoint returns correct information."""
        url = reverse('api-root')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('version', response.data)
        self.assertIn('documentation', response.data)
        self.assertEqual(response.data['message'], 'Welcome to the CustodyCoach API')
        self.assertEqual(response.data['version'], '1.0.0')

    def test_health_check(self):
        """Test the health check endpoint."""
        url = reverse('health-check')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('status', response.data)
        self.assertIn('message', response.data)
        self.assertEqual(response.data['status'], 'healthy')
        self.assertEqual(response.data['message'], 'CustodyCoach API is running')

    def test_api_schema_accessible(self):
        """Test that the OpenAPI schema endpoint is accessible."""
        response = self.client.get('/api/schema/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_swagger_ui_accessible(self):
        """Test that the Swagger UI is accessible."""
        response = self.client.get('/api/docs/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_redoc_accessible(self):
        """Test that the ReDoc interface is accessible."""
        response = self.client.get('/api/redoc/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
