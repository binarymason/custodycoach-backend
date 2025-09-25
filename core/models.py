from django.db import models
from django.contrib.auth.models import User


class Label(models.Model):
    """
    Model for event labels/tags.
    """
    name = models.CharField(max_length=50, unique=True)
    color = models.CharField(max_length=7, default='#007bff', help_text='Hex color code')
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name


class Participant(models.Model):
    """
    Model for event participants.
    """
    name = models.CharField(max_length=100)
    email = models.EmailField(blank=True, null=True)
    role = models.CharField(max_length=50, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['name']
    
    def __str__(self):
        return self.name


class Event(models.Model):
    """
    Model for custody coaching events.
    """
    IMPACT_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True, null=True)
    start_date = models.DateTimeField()
    end_date = models.DateTimeField()
    impact = models.CharField(max_length=10, choices=IMPACT_CHOICES, default='medium')
    
    # User who created the event
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='events')
    
    # Many-to-many relationships
    participants = models.ManyToManyField(Participant, blank=True, related_name='events')
    labels = models.ManyToManyField(Label, blank=True, related_name='events')
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-start_date']
    
    def __str__(self):
        return self.title
