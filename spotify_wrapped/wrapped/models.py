from django.db import models
import logging
from django.contrib.auth.models import User
from django.utils import timezone

logger = logging.getLogger(__name__)

class SpotifyUser(models.Model):
    spotify_id = models.CharField(max_length=255, primary_key=True)
    user_name = models.CharField(max_length=255)
    profile_image = models.URLField(max_length=500, null=True, blank=True)  # Add this field
    friends = models.ManyToManyField('self', symmetrical=False, blank=True)
    past_wraps = models.JSONField(default=list)
    last_spotify_wrapped = models.JSONField(default=dict)

    def __str__(self):
        return self.user_name

    def add_friend(self, friend_user):
        """Add a friend and ensure both users are connected"""
        if friend_user != self:
            self.friends.add(friend_user)
            friend_user.friends.add(self)

    def remove_friend(self, friend_user):
        """Remove a friend connection from both users"""
        self.friends.remove(friend_user)
        friend_user.friends.remove(self)

# Signal handler in the same file
from django.db.models.signals import pre_delete
from django.dispatch import receiver

@receiver(pre_delete, sender=SpotifyUser)
def log_user_deletion(sender, instance, **kwargs):
    """Log when a SpotifyUser is about to be deleted"""
    logger.info(f"SpotifyUser deletion triggered for: {instance.user_name} (ID: {instance.spotify_id})")


class Feedback(models.Model):
    STATUS_CHOICES = [
        ('new', 'New'),
        ('read', 'Read'),
        ('responded', 'Responded'),
    ]

    name = models.CharField(max_length=255)
    email = models.EmailField()
    message = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default='new'
    )
    admin_response = models.TextField(blank=True, null=True)
    admin_response_at = models.DateTimeField(blank=True, null=True)
    admin = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='handled_feedbacks'
    )

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Feedback'
        verbose_name_plural = 'Feedbacks'

    def __str__(self):
        return f"Feedback from {self.name} ({self.created_at.strftime('%Y-%m-%d')})"

    def mark_as_responded(self, admin_user, response):
        self.status = 'responded'
        self.admin_response = response
        self.admin_response_at = timezone.now()
        self.admin = admin_user
        self.save()