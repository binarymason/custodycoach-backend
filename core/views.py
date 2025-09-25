from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.viewsets import ModelViewSet
from rest_framework_simplejwt.tokens import RefreshToken
from drf_spectacular.utils import extend_schema, OpenApiResponse
from .models import Event, Participant, Label
from .serializers import (
    UserSignupSerializer, 
    UserLoginSerializer, 
    TokenResponseSerializer,
    UserSerializer,
    LogoutSerializer,
    EventSerializer,
    EventListSerializer,
    ParticipantSerializer,
    LabelSerializer
)


@extend_schema(
    summary="API Root",
    description="Welcome endpoint providing basic information about the CustodyCoach API",
    responses={200: {"description": "API information"}}
)
@api_view(['GET'])
@permission_classes([AllowAny])
def api_root(request):
    """
    Welcome to the CustodyCoach API.
    
    This API provides endpoints for managing custody coaching services.
    """
    return Response({
        'message': 'Welcome to the CustodyCoach API',
        'version': '1.0.0',
        'documentation': {
            'swagger': request.build_absolute_uri('/api/docs/'),
            'redoc': request.build_absolute_uri('/api/redoc/'),
        }
    })


@extend_schema(
    summary="Health Check",
    description="Health check endpoint to verify the API is running",
    responses={200: {"description": "Service is healthy"}}
)
@api_view(['GET'])
@permission_classes([AllowAny])
def health_check(request):
    """
    Health check endpoint to verify the API is running properly.
    """
    return Response({
        'status': 'healthy',
        'message': 'CustodyCoach API is running'
    }, status=status.HTTP_200_OK)


class SignupView(APIView):
    """
    User registration endpoint.
    
    Creates a new user account with email and password.
    """
    permission_classes = [AllowAny]

    @extend_schema(
        summary="User Registration",
        description="Create a new user account with email and password",
        request=UserSignupSerializer,
        responses={
            201: OpenApiResponse(
                response=UserSerializer,
                description="User created successfully"
            ),
            400: OpenApiResponse(description="Validation error")
        },
        tags=['Authentication']
    )
    def post(self, request):
        serializer = UserSignupSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            user_serializer = UserSerializer(user)
            return Response(
                {
                    'message': 'User created successfully',
                    'user': user_serializer.data
                },
                status=status.HTTP_201_CREATED
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginView(APIView):
    """
    User login endpoint.
    
    Authenticates user with email and password, returns JWT tokens.
    """
    permission_classes = [AllowAny]

    @extend_schema(
        summary="User Login",
        description="Authenticate user with email and password, returns JWT access and refresh tokens",
        request=UserLoginSerializer,
        responses={
            200: OpenApiResponse(
                response=TokenResponseSerializer,
                description="Login successful, JWT tokens returned"
            ),
            400: OpenApiResponse(description="Invalid credentials")
        },
        tags=['Authentication']
    )
    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            refresh = RefreshToken.for_user(user)
            
            return Response({
                'message': 'Login successful',
                'access': str(refresh.access_token),
                'refresh': str(refresh),
                'user': {
                    'id': user.id,
                    'email': user.email,
                    'username': user.username,
                }
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    """
    User logout endpoint.
    
    Invalidates the refresh token by blacklisting it.
    """
    permission_classes = [AllowAny]

    @extend_schema(
        summary="User Logout",
        description="Invalidate the current session by blacklisting the refresh token",
        request=LogoutSerializer,
        responses={
            200: OpenApiResponse(description="Logout successful"),
            400: OpenApiResponse(description="Invalid token")
        },
        tags=['Authentication']
    )
    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        if serializer.is_valid():
            try:
                serializer.save()
                return Response(
                    {'message': 'Logout successful'}, 
                    status=status.HTTP_200_OK
                )
            except Exception:
                return Response(
                    {'error': 'Invalid token'}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class MeView(APIView):
    """
    Current user details endpoint.
    
    Returns details of the current user based on the provided JWT token.
    """
    permission_classes = [IsAuthenticated]

    @extend_schema(
        summary="Get Current User",
        description="Get details of the current user based on the JWT token provided in the request",
        responses={
            200: OpenApiResponse(
                response=UserSerializer,
                description="Current user details"
            ),
            401: OpenApiResponse(description="Authentication required")
        },
        tags=['Authentication']
    )
    def get(self, request):
        serializer = UserSerializer(request.user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class EventViewSet(ModelViewSet):
    """
    ViewSet for managing Events.
    
    Provides CRUD operations for events belonging to the authenticated user.
    """
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        """Return events for the current user only."""
        return Event.objects.filter(user=self.request.user).prefetch_related(
            'participants', 'labels'
        )
    
    def get_serializer_class(self):
        """Return appropriate serializer based on action."""
        if self.action == 'list':
            return EventListSerializer
        return EventSerializer
    
    def perform_create(self, serializer):
        """Set the user to the current user when creating an event."""
        serializer.save(user=self.request.user)
    
    @extend_schema(
        summary="List Events",
        description="List all events for the authenticated user",
        responses={
            200: OpenApiResponse(
                response=EventListSerializer(many=True),
                description="List of user's events"
            ),
            401: OpenApiResponse(description="Authentication required")
        },
        tags=['Events']
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)
    
    @extend_schema(
        summary="Create Event",
        description="Create a new event for the authenticated user",
        request=EventSerializer,
        responses={
            201: OpenApiResponse(
                response=EventSerializer,
                description="Event created successfully"
            ),
            400: OpenApiResponse(description="Validation error"),
            401: OpenApiResponse(description="Authentication required")
        },
        tags=['Events']
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)
    
    @extend_schema(
        summary="Get Event Details",
        description="Get full details of a specific event",
        responses={
            200: OpenApiResponse(
                response=EventSerializer,
                description="Event details"
            ),
            404: OpenApiResponse(description="Event not found"),
            401: OpenApiResponse(description="Authentication required")
        },
        tags=['Events']
    )
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)
    
    @extend_schema(
        summary="Update Event",
        description="Update an existing event (partial update supported)",
        request=EventSerializer,
        responses={
            200: OpenApiResponse(
                response=EventSerializer,
                description="Event updated successfully"
            ),
            400: OpenApiResponse(description="Validation error"),
            404: OpenApiResponse(description="Event not found"),
            401: OpenApiResponse(description="Authentication required")
        },
        tags=['Events']
    )
    def partial_update(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)
    
    @extend_schema(
        summary="Delete Event",
        description="Delete an existing event",
        responses={
            204: OpenApiResponse(description="Event deleted successfully"),
            404: OpenApiResponse(description="Event not found"),
            401: OpenApiResponse(description="Authentication required")
        },
        tags=['Events']
    )
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)


class ParticipantViewSet(ModelViewSet):
    """
    ViewSet for managing Participants.
    
    Provides CRUD operations for participants that can be associated with events.
    """
    queryset = Participant.objects.all()
    serializer_class = ParticipantSerializer
    permission_classes = [IsAuthenticated]
    
    @extend_schema(tags=['Participants'])
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)
    
    @extend_schema(tags=['Participants'])
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)
    
    @extend_schema(tags=['Participants'])
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)
    
    @extend_schema(tags=['Participants'])
    def partial_update(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)
    
    @extend_schema(tags=['Participants'])
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)


class LabelViewSet(ModelViewSet):
    """
    ViewSet for managing Labels.
    
    Provides CRUD operations for labels that can be associated with events.
    """
    queryset = Label.objects.all()
    serializer_class = LabelSerializer
    permission_classes = [IsAuthenticated]
    
    @extend_schema(tags=['Labels'])
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)
    
    @extend_schema(tags=['Labels'])
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)
    
    @extend_schema(tags=['Labels'])
    def retrieve(self, request, *args, **kwargs):
        return super().retrieve(request, *args, **kwargs)
    
    @extend_schema(tags=['Labels'])
    def partial_update(self, request, *args, **kwargs):
        return super().partial_update(request, *args, **kwargs)
    
    @extend_schema(tags=['Labels'])
    def destroy(self, request, *args, **kwargs):
        return super().destroy(request, *args, **kwargs)
