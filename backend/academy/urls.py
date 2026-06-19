from django.urls import path
from .views import ModuleListView, ModuleDetailView, ProgressView, QuizSubmitView

urlpatterns = [
    path('modules/', ModuleListView.as_view(), name='module-list'),
    path('modules/<int:pk>/', ModuleDetailView.as_view(), name='module-detail'),
    path('quiz/submit/', QuizSubmitView.as_view(), name='quiz-submit'),
    path('progress/', ProgressView.as_view(), name='progress'), 
]