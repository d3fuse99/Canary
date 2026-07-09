FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .
COPY index.html .
EXPOSE 9090
ENV PYTHONUNBUFFERED=1
CMD ["python", "server.py"]