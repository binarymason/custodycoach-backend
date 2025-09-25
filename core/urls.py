from django.urls import path
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()

# Register ViewSets with the router
router.register(r'events', views.EventViewSet, basename='event')
router.register(r'participants', views.ParticipantViewSet)
router.register(r'labels', views.LabelViewSet)

urlpatterns = [
    path('', views.api_root, name='api-root'),
    path('health/', views.health_check, name='health-check'),
    
    # Authentication routes
    path('auth/signup/', views.SignupView.as_view(), name='auth-signup'),
    path('auth/login/', views.LoginView.as_view(), name='auth-login'),
    path('auth/logout/', views.LogoutView.as_view(), name='auth-logout'),
    path('auth/me/', views.MeView.as_view(), name='auth-me'),
] + router.urls