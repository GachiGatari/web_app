import os

from celery import Celery


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "web_app.settings")
app = Celery("web_app")
app.config_from_object("django.conf:settings", namespace="CELERY")
app.autodiscover_tasks()

app.conf.beat_schedule = {
    'report-every-30-seconds': {
        'task': 'users.tasks.create_report',
        'schedule': 30.0,
    },
    'movies-every-30-seconds': {
        'task': 'users.tasks.parse_movie',
        'schedule': 30.0,
    },
}

app.conf.timezone = 'UTC'