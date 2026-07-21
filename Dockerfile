FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN apt-get update && \
    apt-get install -y libcrypt1 && \
    pip install --upgrade pip && \
    pip install -r requirements.txt && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
COPY . .
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:5001", "--timeout", "300", "app:app"]
