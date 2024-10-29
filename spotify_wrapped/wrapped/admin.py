from django.contrib import admin
from .models import SpotifyUser
from django.utils.html import format_html
from .models import Feedback

@admin.register(SpotifyUser)
class SpotifyUserAdmin(admin.ModelAdmin):
    list_display = ('spotify_id', 'user_name')  # Display fields in the list view
    search_fields = ('spotify_id', 'user_name')  # Add search functionality
    filter_horizontal = ('friends',)  # Enables selection of friends in a UI-friendly way

    # Display the 'past_wraps' field as a JSON field in admin (optional)
    def get_readonly_fields(self, request, obj=None):
        readonly_fields = super().get_readonly_fields(request, obj)
        readonly_fields += ('past_wraps', 'last_spotify_wrapped')
        return readonly_fields



@admin.register(Feedback)
class FeedbackAdmin(admin.ModelAdmin):
    list_display = ('name', 'email', 'created_at', 'status', 'colored_status',
                    'admin_response_preview')
    list_filter = ('status', 'created_at')
    search_fields = ('name', 'email', 'message', 'admin_response')
    readonly_fields = ('created_at',)
    ordering = ('-created_at',)

    fieldsets = (
        ('User Information', {
            'fields': ('name', 'email')
        }),
        ('Feedback Content', {
            'fields': ('message', 'created_at')
        }),
        ('Admin Response', {
            'fields': ('status', 'admin_response', 'admin_response_at', 'admin')
        }),
    )

    def colored_status(self, obj):
        colors = {
            'new': 'red',
            'read': 'orange',
            'responded': 'green'
        }
        return format_html(
            '<span style="color: {};">{}</span>',
            colors[obj.status],
            obj.get_status_display()
        )

    colored_status.short_description = 'Status'

    def admin_response_preview(self, obj):
        if obj.admin_response:
            return obj.admin_response[:50] + '...' if len(
                obj.admin_response) > 50 else obj.admin_response
        return '-'

    admin_response_preview.short_description = 'Response Preview'

    def save_model(self, request, obj, form, change):
        if not obj.admin:
            obj.admin = request.user
        super().save_model(request, obj, form, change)