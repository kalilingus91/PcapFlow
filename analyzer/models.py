from django.db import models
from django.contrib.auth.models import User

class AnalysisReport(models.Model):
    # Уровни угроз для удобной фильтрации (поможет в Visualizations)
    THREAT_CHOICES = [
        ('SAFE', 'Безопасно'),
        ('LOW', 'Низкий риск'),
        ('MEDIUM', 'Средний риск'),
        ('HIGH', 'Высокий риск'),
        ('CRITICAL', 'Критический риск'),
    ]

    # Привязка к пользователю (если он вошел в систему)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    
    # Основная информация о файле
    file_name = models.CharField(max_length=255)
    file_size = models.FloatField(help_text="Размер в МБ")
    total_threats = models.IntegerField(default=0)
    
    # Поле для хранения всех результатов анализа (статистика, DNS, логины)
    # Позволяет хранить сложные структуры данных в формате JSON
    results_json = models.JSONField()
    
    # Дата создания отчета
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        # Сортировка: сначала новые отчеты
        ordering = ['-created_at']

    def __str__(self):
        return f"Отчет: {self.file_name} ({self.created_at.strftime('%d.%m.%Y')})"