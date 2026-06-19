from django.db import models
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError

User = get_user_model()

def validate_video_file(value):
    import os
    ext = os.path.splitext(value.name)[1].lower()
    valid_extensions = ['.mp4', '.webm', '.mov', '.avi']
    if ext not in valid_extensions:
        raise ValidationError('Format non supporté. Utilisez mp4, webm, mov ou avi.')

class Module(models.Model):
    TARGET_CHOICES = [
        ('citizen', 'Citoyen'),
        ('company', 'Entreprise'),
        ('both', 'Tous'),
    ]

    title = models.CharField(max_length=200)
    description = models.TextField()
    content = models.TextField()
    
    # === NOUVEAU CHAMP : Image de couverture du module ===
    image = models.ImageField(
        upload_to='academy/modules/',
        blank=True,
        null=True,
        help_text="Image de couverture du module (vignette)"
    )
    
    # Vidéo en ligne (YouTube, Vimeo)
    video_url = models.URLField(blank=True, null=True, help_text="Lien YouTube ou Vimeo")
    
    # Vidéo locale (upload)
    video_file = models.FileField(
        upload_to='academy/videos/',
        blank=True,
        null=True,
        validators=[validate_video_file],
        help_text="Fichier vidéo (mp4, webm, mov, avi)"
    )
    
    pdf_file = models.FileField(upload_to='academy/pdfs/', blank=True, null=True)
    target_roles = models.CharField(max_length=10, choices=TARGET_CHOICES, default='citizen')
    order = models.PositiveSmallIntegerField(default=0)

    def __str__(self):
        return self.title

    class Meta:
        ordering = ['order']

class Question(models.Model):
    module = models.ForeignKey(Module, on_delete=models.CASCADE, related_name='questions')
    text = models.TextField()
    image = models.ImageField(
        upload_to='academy/questions/',
        blank=True,
        null=True,
        help_text="Image illustrative pour la question (optionnelle)"
    )
    order = models.PositiveSmallIntegerField(default=0)

    def __str__(self):
        return f"{self.module.title} - Q{self.order}"

    class Meta:
        ordering = ['order']

class Choice(models.Model):
    question = models.ForeignKey(Question, on_delete=models.CASCADE, related_name='choices')
    text = models.CharField(max_length=255)
    is_correct = models.BooleanField(default=False)

    def __str__(self):
        return self.text

class QuizResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='quiz_results')
    module = models.ForeignKey(Module, on_delete=models.CASCADE)
    score = models.PositiveSmallIntegerField()
    total = models.PositiveSmallIntegerField()
    completed_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'module')
        ordering = ['-completed_at']