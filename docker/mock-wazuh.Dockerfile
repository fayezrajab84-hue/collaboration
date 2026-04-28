FROM python:3.12-slim

WORKDIR /app

COPY apps/mock-wazuh/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY apps/mock-wazuh/main.py .

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
