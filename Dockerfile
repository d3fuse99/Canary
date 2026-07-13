FROM python:3.10-slim
WORKDIR /app
RUN pip install --no-cache-dir psutil
COPY config.py .
COPY db.py .
COPY monitor.py .
COPY server.py .
COPY index.html .
EXPOSE 9090
ENV PYTHONUNBUFFERED=1
CMD ["python", "server.py"]