FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && useradd --system --uid 10001 --create-home bountydeck
COPY app.py db.py scope.py ./
COPY templates ./templates
COPY static ./static
RUN mkdir -p /data && chown -R bountydeck:bountydeck /app /data
# Stamped by update.sh so the in-app "Check for updates" button knows which commit is running.
ARG GIT_SHA=dev
ENV BOUNTYDECK_VERSION=${GIT_SHA}
USER bountydeck
EXPOSE 8000
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "2", "--access-logfile", "-", "app:app"]
