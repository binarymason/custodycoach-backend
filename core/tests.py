from django.test import TestCase
from django.urls import reverse
from django.contrib.auth.models import User
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import datetime, timedelta
from django.utils import timezone
import json
from .models import Event, Participant, Label


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
        self.me_url = reverse('auth-me')
        
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

    def test_me_endpoint_authenticated(self):
        """Test GET /api/auth/me with valid JWT token."""
        # Create user and get access token
        user = User.objects.create_user(
            username='test@example.com',
            email='test@example.com',
            password='testpassword123'
        )
        
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        
        # Make authenticated request
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        response = self.client.get(self.me_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('id', response.data)
        self.assertIn('email', response.data)
        self.assertIn('username', response.data)
        self.assertIn('date_joined', response.data)
        self.assertEqual(response.data['email'], 'test@example.com')
        self.assertEqual(response.data['username'], 'test@example.com')
        self.assertEqual(response.data['id'], user.id)

    def test_me_endpoint_unauthenticated(self):
        """Test GET /api/auth/me without authentication."""
        response = self.client.get(self.me_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_me_endpoint_invalid_token(self):
        """Test GET /api/auth/me with invalid JWT token."""
        # Use invalid token
        self.client.credentials(HTTP_AUTHORIZATION='Bearer invalid_token')
        response = self.client.get(self.me_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_complete_auth_flow_with_me(self):
        """Test complete flow: signup -> login -> me -> logout."""
        # 1. Signup
        signup_response = self.client.post(self.signup_url, self.valid_user_data, format='json')
        self.assertEqual(signup_response.status_code, status.HTTP_201_CREATED)
        
        # 2. Login
        login_response = self.client.post(self.login_url, self.login_data, format='json')
        self.assertEqual(login_response.status_code, status.HTTP_200_OK)
        
        access_token = login_response.data['access']
        refresh_token = login_response.data['refresh']
        
        # 3. Get current user info
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        me_response = self.client.get(self.me_url)
        self.assertEqual(me_response.status_code, status.HTTP_200_OK)
        self.assertEqual(me_response.data['email'], 'test@example.com')
        
        # 4. Logout
        logout_data = {'refresh': refresh_token}
        logout_response = self.client.post(self.logout_url, logout_data, format='json')
        self.assertEqual(logout_response.status_code, status.HTTP_200_OK)


class EventAPITest(APITestCase):
    """Test cases for Event API endpoints."""
    
    def setUp(self):
        """Set up test data."""
        # Create test users
        self.user1 = User.objects.create_user(
            username='user1@example.com',
            email='user1@example.com',
            password='testpassword123'
        )
        self.user2 = User.objects.create_user(
            username='user2@example.com',
            email='user2@example.com',
            password='testpassword123'
        )
        
        # URLs
        self.events_url = reverse('event-list')
        
        # Create test participants and labels
        self.participant1 = Participant.objects.create(
            name='John Doe',
            email='john@example.com',
            role='Attorney'
        )
        self.participant2 = Participant.objects.create(
            name='Jane Smith',
            email='jane@example.com',
            role='Mediator'
        )
        
        self.label1 = Label.objects.create(name='Urgent', color='#ff0000')
        self.label2 = Label.objects.create(name='Meeting', color='#00ff00')
        
        # Create test events
        now = timezone.now()
        self.event1 = Event.objects.create(
            title='Court Hearing',
            description='Initial custody hearing',
            start_date=now + timedelta(days=1),
            end_date=now + timedelta(days=1, hours=2),
            impact='high',
            user=self.user1
        )
        self.event1.participants.add(self.participant1)
        self.event1.labels.add(self.label1)
        
        self.event2 = Event.objects.create(
            title='Mediation Session',
            description='Family mediation session',
            start_date=now + timedelta(days=2),
            end_date=now + timedelta(days=2, hours=3),
            impact='medium',
            user=self.user2  # Different user
        )
        
        # Authentication
        self.authenticate_user1()
    
    def authenticate_user1(self):
        """Authenticate as user1."""
        refresh = RefreshToken.for_user(self.user1)
        access_token = str(refresh.access_token)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
    
    def authenticate_user2(self):
        """Authenticate as user2."""
        refresh = RefreshToken.for_user(self.user2)
        access_token = str(refresh.access_token)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
    
    def test_list_events_authenticated(self):
        """Test GET /api/events - List events for authenticated user."""
        response = self.client.get(self.events_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)  # Only user1's event
        self.assertEqual(response.data['results'][0]['title'], 'Court Hearing')
        self.assertEqual(response.data['results'][0]['participants_count'], 1)
        self.assertEqual(response.data['results'][0]['labels_count'], 1)
    
    def test_list_events_unauthenticated(self):
        """Test GET /api/events without authentication."""
        self.client.credentials()  # Remove authentication
        response = self.client.get(self.events_url)
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
    
    def test_create_event(self):
        """Test POST /api/events - Create new event."""
        now = timezone.now()
        event_data = {
            'title': 'New Consultation',
            'description': 'Initial consultation meeting',
            'start_date': (now + timedelta(days=3)).isoformat(),
            'end_date': (now + timedelta(days=3, hours=1)).isoformat(),
            'impact': 'low',
            'participant_ids': [self.participant1.id, self.participant2.id],
            'label_ids': [self.label1.id, self.label2.id]
        }
        
        response = self.client.post(self.events_url, event_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['title'], 'New Consultation')
        self.assertEqual(response.data['impact'], 'low')
        self.assertEqual(len(response.data['participants']), 2)
        self.assertEqual(len(response.data['labels']), 2)
        
        # Verify event was created in database
        event = Event.objects.get(id=response.data['id'])
        self.assertEqual(event.user, self.user1)
        self.assertEqual(event.participants.count(), 2)
        self.assertEqual(event.labels.count(), 2)
    
    def test_create_event_validation_error(self):
        """Test POST /api/events with validation error (end_date before start_date)."""
        now = timezone.now()
        event_data = {
            'title': 'Invalid Event',
            'start_date': (now + timedelta(days=3)).isoformat(),
            'end_date': (now + timedelta(days=2)).isoformat(),  # Before start_date
            'impact': 'low'
        }
        
        response = self.client.post(self.events_url, event_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('End date must be after start date', str(response.data))
    
    def test_get_event_detail(self):
        """Test GET /api/events/:id - Get event details."""
        url = reverse('event-detail', kwargs={'pk': self.event1.id})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], 'Court Hearing')
        self.assertEqual(response.data['description'], 'Initial custody hearing')
        self.assertEqual(response.data['impact'], 'high')
        self.assertEqual(len(response.data['participants']), 1)
        self.assertEqual(len(response.data['labels']), 1)
        self.assertEqual(response.data['participants'][0]['name'], 'John Doe')
        self.assertEqual(response.data['labels'][0]['name'], 'Urgent')
    
    def test_get_event_detail_not_found(self):
        """Test GET /api/events/:id with non-existent event."""
        url = reverse('event-detail', kwargs={'pk': 99999})
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
    
    def test_get_event_detail_different_user(self):
        """Test GET /api/events/:id for event belonging to different user."""
        url = reverse('event-detail', kwargs={'pk': self.event2.id})
        response = self.client.get(url)
        
        # Should return 404 since event belongs to user2, not user1
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
    
    def test_update_event(self):
        """Test PATCH /api/events/:id - Update event."""
        url = reverse('event-detail', kwargs={'pk': self.event1.id})
        update_data = {
            'title': 'Updated Court Hearing',
            'impact': 'critical',
            'participant_ids': [self.participant2.id],  # Change participants
            'label_ids': [self.label2.id]  # Change labels
        }
        
        response = self.client.patch(url, update_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['title'], 'Updated Court Hearing')
        self.assertEqual(response.data['impact'], 'critical')
        self.assertEqual(len(response.data['participants']), 1)
        self.assertEqual(response.data['participants'][0]['name'], 'Jane Smith')
        self.assertEqual(len(response.data['labels']), 1)
        self.assertEqual(response.data['labels'][0]['name'], 'Meeting')
        
        # Verify changes in database
        self.event1.refresh_from_db()
        self.assertEqual(self.event1.title, 'Updated Court Hearing')
        self.assertEqual(self.event1.impact, 'critical')
    
    def test_update_event_different_user(self):
        """Test PATCH /api/events/:id for event belonging to different user."""
        url = reverse('event-detail', kwargs={'pk': self.event2.id})
        update_data = {'title': 'Should not update'}
        
        response = self.client.patch(url, update_data, format='json')
        
        # Should return 404 since event belongs to user2, not user1
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
    
    def test_delete_event(self):
        """Test DELETE /api/events/:id - Delete event."""
        url = reverse('event-detail', kwargs={'pk': self.event1.id})
        
        response = self.client.delete(url)
        
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        
        # Verify event was deleted
        self.assertFalse(Event.objects.filter(id=self.event1.id).exists())
    
    def test_user_isolation(self):
        """Test that users can only see their own events."""
        # Create events for both users
        now = timezone.now()
        Event.objects.create(
            title='User1 Event',
            start_date=now,
            end_date=now + timedelta(hours=1),
            user=self.user1
        )
        Event.objects.create(
            title='User2 Event',
            start_date=now,
            end_date=now + timedelta(hours=1),
            user=self.user2
        )
        
        # Test as user1
        self.authenticate_user1()
        response = self.client.get(self.events_url)
        titles = [event['title'] for event in response.data['results']]
        self.assertIn('User1 Event', titles)
        self.assertIn('Court Hearing', titles)  # Existing user1 event
        self.assertNotIn('User2 Event', titles)
        self.assertNotIn('Mediation Session', titles)  # Existing user2 event
        
        # Test as user2
        self.authenticate_user2()
        response = self.client.get(self.events_url)
        titles = [event['title'] for event in response.data['results']]
        self.assertIn('User2 Event', titles)
        self.assertIn('Mediation Session', titles)  # Existing user2 event
        self.assertNotIn('User1 Event', titles)
        self.assertNotIn('Court Hearing', titles)  # Existing user1 event


class ParticipantAPITest(APITestCase):
    """Test cases for Participant API endpoints."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='test@example.com',
            email='test@example.com',
            password='testpassword123'
        )
        
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        self.participants_url = reverse('participant-list')
    
    def test_list_participants(self):
        """Test GET /api/participants."""
        Participant.objects.create(name='John Doe', email='john@example.com')
        Participant.objects.create(name='Jane Smith', email='jane@example.com')
        
        response = self.client.get(self.participants_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)
    
    def test_create_participant(self):
        """Test POST /api/participants."""
        participant_data = {
            'name': 'New Participant',
            'email': 'new@example.com',
            'role': 'Attorney'
        }
        
        response = self.client.post(self.participants_url, participant_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'New Participant')
        self.assertEqual(response.data['email'], 'new@example.com')
        self.assertEqual(response.data['role'], 'Attorney')


class LabelAPITest(APITestCase):
    """Test cases for Label API endpoints."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='test@example.com',
            email='test@example.com',
            password='testpassword123'
        )
        
        refresh = RefreshToken.for_user(self.user)
        access_token = str(refresh.access_token)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {access_token}')
        
        self.labels_url = reverse('label-list')
    
    def test_list_labels(self):
        """Test GET /api/labels."""
        Label.objects.create(name='Urgent', color='#ff0000')
        Label.objects.create(name='Important', color='#00ff00')
        
        response = self.client.get(self.labels_url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 2)
    
    def test_create_label(self):
        """Test POST /api/labels."""
        label_data = {
            'name': 'New Label',
            'color': '#0000ff'
        }
        
        response = self.client.post(self.labels_url, label_data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['name'], 'New Label')
        self.assertEqual(response.data['color'], '#0000ff')
