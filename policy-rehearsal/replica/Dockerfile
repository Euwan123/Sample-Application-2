FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY policies ./policies
COPY simulator ./simulator
COPY replica ./replica

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
EXPOSE 8000

CMD ["uvicorn", "replica.main:app", "--host", "0.0.0.0", "--port", "8000"]
