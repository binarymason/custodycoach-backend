from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from drf_spectacular.utils import extend_schema, OpenApiResponse
from .serializers import (
    UserSignupSerializer, 
    UserLoginSerializer, 
    TokenResponseSerializer,
    UserSerializer,
    LogoutSerializer
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
