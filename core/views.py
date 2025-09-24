from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework import status
from drf_spectacular.utils import extend_schema


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
