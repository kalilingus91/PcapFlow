from django.urls import path
from . import views

urlpatterns = [
    # Главная
    path('', views.home_view, name='home'),
    
    # Анализ и Отчеты
    path('analyze/', views.analyze_file, name='analyze_file'),
    path('report/<int:report_id>/', views.report_detail, name='report_detail'),
    path('history/', views.history_view, name='history'),
    path('history/delete/<int:report_id>/', views.delete_report, name='delete_report'),
    path('history/clear/', views.clear_history, name='clear_history'),

    # Регистрация (ВОТ ОНА!)
    path('register/', views.register_view, name='register'),
]