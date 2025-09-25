from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
import json


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


class AuthenticationTest(APITestCase):
    """Test cases for authentication endpoints."""

    def setUp(self):
        """Set up test data."""
        self.signup_url = reverse('auth-signup')
        self.login_url = reverse('auth-login')
        self.logout_url = reverse('auth-logout')
        
        self.valid_user_data = {
            'email': 'test@example.com',
            'password': 'testpassword123',
            'password_confirm': 'testpassword123'
        }
        
        self.login_data = {
            'email': 'test@example.com',
            'password': 'testpassword123'
        }

    def test_user_signup_success(self):
        """Test successful user registration."""
        response = self.client.post(self.signup_url, self.valid_user_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertIn('message', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['message'], 'User created successfully')
        self.assertEqual(response.data['user']['email'], 'test@example.com')
        
        # Verify user was created in database
        self.assertTrue(User.objects.filter(email='test@example.com').exists())

    def test_user_signup_duplicate_email(self):
        """Test registration with duplicate email."""
        # Create first user
        self.client.post(self.signup_url, self.valid_user_data, format='json')
        
        # Try to create another user with same email
        response = self.client.post(self.signup_url, self.valid_user_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('email', response.data)

    def test_user_signup_password_mismatch(self):
        """Test registration with mismatched passwords."""
        invalid_data = self.valid_user_data.copy()
        invalid_data['password_confirm'] = 'differentpassword'
        
        response = self.client.post(self.signup_url, invalid_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)

    def test_user_signup_short_password(self):
        """Test registration with short password."""
        invalid_data = self.valid_user_data.copy()
        invalid_data['password'] = '123'
        invalid_data['password_confirm'] = '123'
        
        response = self.client.post(self.signup_url, invalid_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('password', response.data)

    def test_user_login_success(self):
        """Test successful user login."""
        # Create user first
        User.objects.create_user(
            username='test@example.com',
            email='test@example.com',
            password='testpassword123'
        )
        
        response = self.client.post(self.login_url, self.login_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.data)
        self.assertIn('user', response.data)
        self.assertEqual(response.data['message'], 'Login successful')

    def test_user_login_invalid_credentials(self):
        """Test login with invalid credentials."""
        invalid_login = {
            'email': 'nonexistent@example.com',
            'password': 'wrongpassword'
        }
        
        response = self.client.post(self.login_url, invalid_login, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)

    def test_user_login_wrong_password(self):
        """Test login with correct email but wrong password."""
        # Create user first
        User.objects.create_user(
            username='test@example.com',
            email='test@example.com',
            password='testpassword123'
        )
        
        wrong_password_data = {
            'email': 'test@example.com',
            'password': 'wrongpassword'
        }
        
        response = self.client.post(self.login_url, wrong_password_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('non_field_errors', response.data)

    def test_user_logout_success(self):
        """Test successful user logout."""
        # Create user and get refresh token
        user = User.objects.create_user(
            username='test@example.com',
            email='test@example.com',
            password='testpassword123'
        )
        
        refresh = RefreshToken.for_user(user)
        logout_data = {'refresh': str(refresh)}
        
        response = self.client.post(self.logout_url, logout_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('message', response.data)
        self.assertEqual(response.data['message'], 'Logout successful')

    def test_user_logout_invalid_token(self):
        """Test logout with invalid refresh token."""
        invalid_logout_data = {'refresh': 'invalid_token'}
        
        response = self.client.post(self.logout_url, invalid_logout_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('error', response.data)

    def test_full_auth_flow(self):
        """Test complete authentication flow: signup -> login -> logout."""
        # 1. Signup
        signup_response = self.client.post(self.signup_url, self.valid_user_data, format='json')
        self.assertEqual(signup_response.status_code, status.HTTP_201_CREATED)
        
        # 2. Login
        login_response = self.client.post(self.login_url, self.login_data, format='json')
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        
        refresh_token = login_response.data['refresh']
        
        # 3. Logout
        logout_data = {'refresh': refresh_token}
        logout_response = self.client.post(self.logout_url, logout_data, format='json')
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)
