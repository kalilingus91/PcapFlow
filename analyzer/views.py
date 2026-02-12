from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth import login
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import AnalysisReport

# импорт логики анализатора из папки services
from .services.pcap_analyzer import run_pcap_analysis


# 1. ГЛАВНАЯ СТРАНИЦА

def home_view(request):
    """отображает страницу загрузки файла."""
    return render(request, 'index.html')


# 2. АНАЛИЗ ФАЙЛА (CORE LOGIC)

def analyze_file(request):
    """
    тут анализатор принимает файл, отправляет и его в сервис PcapAnalyzer,
    сохраняет результат в базу данных.
    """
    if request.method == 'POST' and request.FILES.get('file'):
        uploaded_file = request.FILES['file']
        
        try:
            # вызываем наш упрощенный сервис анализа
            # он вернет словарь с результатами
            results = run_pcap_analysis(uploaded_file)
            
            # создание записи в базе данных (модель AnalysisReport)
            report = AnalysisReport.objects.create(
                user=request.user if request.user.is_authenticated else None,
                file_name=uploaded_file.name,
                file_size=round(uploaded_file.size / (1024 * 1024), 2),
                results_json=results,
                total_threats=len(results.get('threats', []))
            )
            
            # добавляем сообщение об успехе 
            messages.success(request, f" {uploaded_file.name} File succesfully analyzed!")
            
            # переходим на страницу с деталями этого отчета
            return redirect('report_detail', report_id=report.id)
            
        except Exception as e:
            # на случай если вдруг что-то пошло не так (ошибка парсинга и т.д.)
            return render(request, 'index.html', {'error': f"Ошибка при анализе: {str(e)}"})
            
    # если зашли просто через URL или без файла возвращаемся на главную
    return redirect('home')


# 3. REPORT
def report_detail(request, report_id):
    """Отображает результаты конкретного анализа."""
    report = get_object_or_404(AnalysisReport, pk=report_id)
    
    # передаем в шаблон сам отчет и отдельно JSON-данные для удобства
    context = {
        'info': report,
        'results': report.results_json,
        'has_threats': report.total_threats > 0
    }
    return render(request, 'report.html', context)


# 4. HISTORY
def history_view(request):
    """Показывает список всех предыдущих анализов пользователя."""
    if request.user.is_authenticated:
        # если юзер залогинен - берем только его отчеты
        reports = AnalysisReport.objects.filter(user=request.user).order_by('-created_at')
    else:
        # если нет - история пуста 
        reports = []
        
    return render(request, 'history.html', {'reports': reports})

@login_required
def delete_report(request, report_id):
    if request.method == 'POST':
        # находим отчет, принадлежащий именно текущему юзеру
        report = get_object_or_404(AnalysisReport, id=report_id, user=request.user)
        report.delete()
    return redirect('history')

@login_required
def clear_history(request):
    if request.method == 'POST':
        # удаляем все отчеты текущего пользователя
        AnalysisReport.objects.filter(user=request.user).delete()
    return redirect('history')

# 5. РЕГИСТРАЦИЯ 

def register_view(request):
    """Создание нового аккаунта."""
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user) # cразу логиним после регистрации
            return redirect('home')
    else:
        form = UserCreationForm()
    
    return render(request, 'register.html', {'form': form})