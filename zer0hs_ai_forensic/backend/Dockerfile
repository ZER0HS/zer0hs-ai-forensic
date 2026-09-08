FROM python:3.13-slim

WORKDIR /app

# System deps: none needed beyond what the slim image already has —
# everything here is pure Python / httpx.

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Baked into the image, not a secret — the API key itself comes from the
# environment at `docker run`/compose time (see .env.example).
ENV PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
