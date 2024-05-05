import time
import requests

from celery import shared_task
from django.db.models import Count
from bs4 import BeautifulSoup

from users.models import LogUnit


@shared_task
def create_task(task_type):
    time.sleep(int(task_type) * 10)
    return True

@shared_task
def create_report():
    """
    Create report with rating methods by number of they call
    Report writing to report.txt
    """
    method_name_count = LogUnit.objects.values('method_name').annotate(count=Count('method_name')).order_by('-count')
    print(method_name_count)
    msg = ""
    for i, log in enumerate(method_name_count):
        msg += f"{i+1}) {log['method_name']} - {log['count']}\n"
    with open("report.txt", 'w') as f:
        f.write(msg)
    return True

@shared_task
def parse_movie():
    """
    Parse Kinostar86 afisha and writing short info about movies in movies.txt
    """
    url = "https://kinostar86.ru/events?facility=kinostar"
    response = requests.get(url)
    print(response)
    if response.status_code != 200:
        return False
    bs = BeautifulSoup(response.text, "lxml")
    all_movies = bs.find_all('div', {"class": "sc-779c5110-1 gksQcf event-calendar-item"})
    movie_list = []
    msg = "Афиша кинотеатра Киностар\n"
    for movie in all_movies:
        title = movie.find("h2", {"class": "sc-e179c6c0-0 cAQyjf title"}).find("a").text
        view_from, view_to, duration = [x.text for x in movie.find_all("div", {"class": "sc-9a910ef6-3 hQnRyc"})[:3]]
        sinopsis = movie.find("div", {"class": "sc-779c5110-8 bZgsBc"}).find("div").text[:97] + "..."
        movie_list.append({
            "title": title,
            "view_from": view_from,
            "view_to": view_to,
            "duration": duration,
            "sinopsis": sinopsis
        })
    for i, movie in enumerate(movie_list):
        msg += f"        №{i+1}        \n" \
               f"----------------------\n" \
               f"Название: {movie['title']}\n" \
               f"В прокате с: {movie['view_from']}\n" \
               f"В прокате до: {movie['view_to']}\n" \
               f"Хронометраж: {movie['duration']}\n" \
               f"Краткое описание: {movie['sinopsis']}\n" \
               f"----------------------\n"
    with open("movies.txt", 'w') as f:
        f.write(msg)

