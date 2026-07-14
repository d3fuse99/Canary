FROM python:3.10-slim
WORKDIR /app
ENV SENTRY_VERSION=1.3.1
ENV PYTHONUNBUFFERED=1
RUN pip install --no-cache-dir psutil==5.9.8
COPY config.py .
COPY db.py .
COPY monitor.py .
COPY server.py .
COPY index.html .
EXPOSE 9090
CMD ["python", "server.py"]