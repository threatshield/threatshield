FROM python:3.10-slim
WORKDIR /app
COPY requirements.txt .
RUN apt-get update && \
    apt-get install -y libcrypt1 && \
    pip install --upgrade pip && \
    pip install -r requirements.txt && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
COPY . .
EXPOSE 5001
CMD ["python3", "app.py"]
