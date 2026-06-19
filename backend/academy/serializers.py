from rest_framework import serializers
from .models import Module, Question, Choice, QuizResult

class ChoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Choice
        fields = ['id', 'text', 'is_correct']

class QuestionSerializer(serializers.ModelSerializer):
    choices = ChoiceSerializer(many=True, read_only=True)

    class Meta:
        model = Question
        fields = ['id', 'text', 'image', 'choices']

class ModuleListSerializer(serializers.ModelSerializer):
    question_count = serializers.IntegerField(source='questions.count', read_only=True)

    class Meta:
        model = Module
        fields = ['id', 'title', 'description', 'order', 'question_count', 'image', 'video_url', 'video_file', 'pdf_file']

class ModuleDetailSerializer(serializers.ModelSerializer):
    questions = QuestionSerializer(many=True, read_only=True)

    class Meta:
        model = Module
        fields = ['id', 'title', 'description', 'content', 'order', 'image', 'video_url', 'video_file', 'pdf_file', 'questions']
class QuizSubmitSerializer(serializers.Serializer):
    module_id = serializers.IntegerField()
    answers = serializers.DictField(child=serializers.IntegerField())

class QuizResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = QuizResult
        fields = ['module', 'score', 'total', 'completed_at']