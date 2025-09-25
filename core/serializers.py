from rest_framework import serializers
from django.contrib.auth.models import User
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .models import Event, Participant, Label


class UserSignupSerializer(serializers.ModelSerializer):
    """Serializer for user registration."""
    password = serializers.CharField(write_only=True, min_length=8)
    password_confirm = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = ('email', 'password', 'password_confirm')

    def validate_email(self, value):
        """Validate that email is unique."""
        if User.objects.filter(email=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value

    def validate(self, attrs):
        """Validate that passwords match."""
        if attrs['password'] != attrs['password_confirm']:
            raise serializers.ValidationError("Passwords do not match.")
        return attrs

    def create(self, validated_data):
        """Create and return a new user."""
        validated_data.pop('password_confirm')
        email = validated_data.pop('email')
        password = validated_data.pop('password')
        
        # Use email as username since Django requires it
        user = User.objects.create_user(
            username=email,
            email=email,
            password=password
        )
        return user


class UserLoginSerializer(serializers.Serializer):
    """Serializer for user login."""
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        """Validate user credentials."""
        email = attrs.get('email')
        password = attrs.get('password')

        if email and password:
            # Try to find user by email
            try:
                user = User.objects.get(email=email)
                username = user.username
            except User.DoesNotExist:
                raise serializers.ValidationError("Invalid email or password.")

            # Authenticate using username
            user = authenticate(username=username, password=password)
            if not user:
                raise serializers.ValidationError("Invalid email or password.")
            
            if not user.is_active:
                raise serializers.ValidationError("User account is disabled.")
            
            attrs['user'] = user
        else:
            raise serializers.ValidationError("Must include email and password.")

        return attrs


class TokenResponseSerializer(serializers.Serializer):
    """Serializer for JWT token response."""
    access = serializers.CharField()
    refresh = serializers.CharField()
    user = serializers.SerializerMethodField()

    def get_user(self, obj):
        """Return user information."""
        user = obj.get('user')
        if user:
            return {
                'id': user.id,
                'email': user.email,
                'username': user.username,
            }
        return None


class UserSerializer(serializers.ModelSerializer):
    """Serializer for user information."""
    class Meta:
        model = User
        fields = ('id', 'email', 'username', 'date_joined')
        read_only_fields = ('id', 'date_joined')


class LogoutSerializer(serializers.Serializer):
    """Serializer for logout request."""
    refresh = serializers.CharField()

    def validate(self, attrs):
        """Validate refresh token."""
        self.token = attrs['refresh']
        return attrs

    def save(self, **kwargs):
        """Blacklist the refresh token."""
        try:
            RefreshToken(self.token).blacklist()
        except Exception as e:
            raise serializers.ValidationError("Invalid token.")


class LabelSerializer(serializers.ModelSerializer):
    """Serializer for Label model."""
    
    class Meta:
        model = Label
        fields = ('id', 'name', 'color', 'created_at')
        read_only_fields = ('id', 'created_at')


class ParticipantSerializer(serializers.ModelSerializer):
    """Serializer for Participant model."""
    
    class Meta:
        model = Participant
        fields = ('id', 'name', 'email', 'role', 'created_at')
        read_only_fields = ('id', 'created_at')


class EventSerializer(serializers.ModelSerializer):
    """Serializer for Event model."""
    participants = ParticipantSerializer(many=True, read_only=True)
    labels = LabelSerializer(many=True, read_only=True)
    participant_ids = serializers.PrimaryKeyRelatedField(
        queryset=Participant.objects.all(), 
        many=True, 
        write_only=True, 
        required=False,
        source='participants'
    )
    label_ids = serializers.PrimaryKeyRelatedField(
        queryset=Label.objects.all(), 
        many=True, 
        write_only=True, 
        required=False,
        source='labels'
    )
    user = serializers.StringRelatedField(read_only=True)
    
    class Meta:
        model = Event
        fields = (
            'id', 'title', 'description', 'start_date', 'end_date', 
            'impact', 'user', 'participants', 'labels', 
            'participant_ids', 'label_ids', 'created_at', 'updated_at'
        )
        read_only_fields = ('id', 'user', 'created_at', 'updated_at')
    
    def validate(self, attrs):
        """Validate that end_date is after start_date."""
        start_date = attrs.get('start_date')
        end_date = attrs.get('end_date')
        
        if start_date and end_date and end_date <= start_date:
            raise serializers.ValidationError("End date must be after start date.")
        
        return attrs


class EventListSerializer(serializers.ModelSerializer):
    """Lightweight serializer for Event list view."""
    participants_count = serializers.SerializerMethodField()
    labels_count = serializers.SerializerMethodField()
    
    class Meta:
        model = Event
        fields = (
            'id', 'title', 'start_date', 'end_date', 'impact', 
            'participants_count', 'labels_count', 'created_at'
        )
        read_only_fields = fields
    
    def get_participants_count(self, obj):
        """Return count of participants."""
        return obj.participants.count()
    
    def get_labels_count(self, obj):
        """Return count of labels."""
        return obj.labels.count()