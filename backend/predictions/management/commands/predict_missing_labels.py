# predictions/management/commands/predict_missing_labels.py

from django.core.management.base import BaseCommand
from predictions.models import NetworkSession
from predictions import model_utils

class Command(BaseCommand):
    help = 'Predict labels for NetworkSession instances that have no label'

    def handle(self, *args, **options):
        sessions_without_label = NetworkSession.objects.filter(label__isnull=True)
        total = sessions_without_label.count()
        self.stdout.write(f'Found {total} sessions without label.')

        for instance in sessions_without_label:
            data = instance.prepare_data()
            predicted_labels = model_utils.predict(data)
            predicted_label = predicted_labels[0]
            instance.label = predicted_label
            instance.save(update_fields=['label'])
            self.stdout.write(f'Predicted label for session {instance.pk}.')

        self.stdout.write('All missing labels have been predicted.')