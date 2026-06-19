from django.contrib import admin
from .models import Module, Question, Choice, QuizResult

class ModuleAdmin(admin.ModelAdmin):
    list_display = ('title', 'order', 'target_roles', 'image_preview', 'video_url', 'video_file', 'pdf_file')
    fields = ('title', 'description', 'content', 'image', 'video_url', 'video_file', 'pdf_file', 'target_roles', 'order')
    search_fields = ('title', 'description')
    list_filter = ('target_roles',)

    def image_preview(self, obj):
        if obj.image:
            from django.utils.html import format_html
            return format_html('<img src="{}" width="50" height="50" style="object-fit:cover;border-radius:4px;"/>', obj.image.url)
        return "-"
    image_preview.short_description = "Aperçu"
class QuestionAdmin(admin.ModelAdmin):
    list_display = ('module', 'text', 'order', 'image')
    fields = ('module', 'text', 'image', 'order')

class ChoiceAdmin(admin.ModelAdmin):
    list_display = ('question', 'text', 'is_correct')

admin.site.register(Module, ModuleAdmin)
admin.site.register(Question, QuestionAdmin)
admin.site.register(Choice, ChoiceAdmin)
admin.site.register(QuizResult)