from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView
from django.shortcuts import get_object_or_404
from .models import Module, Question, Choice, QuizResult
from .serializers import (
    ModuleListSerializer, ModuleDetailSerializer,
    QuizSubmitSerializer, QuizResultSerializer
)


class ModuleListView(generics.ListAPIView):
    serializer_class = ModuleListSerializer
    permission_classes = [permissions.AllowAny]

    def get_queryset(self):
        user = self.request.user
        if user.is_authenticated:
            if user.role == 'company':
                return Module.objects.filter(target_roles__in=['company', 'both'])
            else:
                return Module.objects.filter(target_roles__in=['citizen', 'both'])
        return Module.objects.filter(target_roles__in=['citizen', 'both'])


class ModuleDetailView(generics.RetrieveAPIView):
    queryset = Module.objects.all()
    serializer_class = ModuleDetailSerializer
    permission_classes = [permissions.AllowAny]


class QuizSubmitView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request):
        serializer = QuizSubmitSerializer(data=request.data)
        if not serializer.is_valid():
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

        module_id = serializer.validated_data['module_id']
        answers = serializer.validated_data['answers']

        module = get_object_or_404(Module, id=module_id)
        questions = module.questions.all()

        if len(answers) != questions.count():
            return Response(
                {"error": "Vous devez répondre à toutes les questions."},
                status=status.HTTP_400_BAD_REQUEST
            )

        score = 0
        total = questions.count()
        details = []

        for question in questions:
            choice_id = answers.get(str(question.id))
            if choice_id is None:
                return Response(
                    {"error": f"Question {question.id} sans réponse."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            try:
                choice = Choice.objects.get(id=choice_id, question=question)
            except Choice.DoesNotExist:
                return Response(
                    {"error": f"Choix invalide pour la question {question.id}."},
                    status=status.HTTP_400_BAD_REQUEST
                )
            is_correct = choice.is_correct
            if is_correct:
                score += 1
            details.append({
                "question_id": question.id,
                "selected_choice_id": choice.id,
                "is_correct": is_correct
            })

        # Enregistrer le résultat
        result, created = QuizResult.objects.update_or_create(
            user=request.user,
            module=module,
            defaults={'score': score, 'total': total}
        )

        # Condition de réussite (majorité simple)
        passed = score > (total / 2)

        return Response({
            "score": score,
            "total": total,
            "passed": passed,
            "details": details,
            "message": "Félicitations, vous avez réussi !" if passed else "Vous pouvez réessayer pour améliorer votre score."
        })


class ProgressView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        results = QuizResult.objects.filter(user=request.user)
        completed_ids = []
        for result in results:
            # Même condition que QuizSubmitView
            passed = result.score > (result.total / 2)
            if passed:
                completed_ids.append(result.module_id)
        return Response({'completed': completed_ids})