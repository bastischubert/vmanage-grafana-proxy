FROM python:3.12-slim

# Create a non-root user
RUN useradd --create-home --shell /bin/bash appuser

WORKDIR /app

# Install dependencies first for better layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY proxy.py .

# Drop privileges
USER appuser

EXPOSE 8080

CMD ["uvicorn", "proxy:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log"]
