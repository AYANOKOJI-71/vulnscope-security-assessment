FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml ./
COPY apps/api/src ./apps/api/src
RUN pip install --no-cache-dir .

EXPOSE 4700
CMD ["uvicorn", "vulnscope.main:app", "--host", "0.0.0.0", "--port", "4700"]
