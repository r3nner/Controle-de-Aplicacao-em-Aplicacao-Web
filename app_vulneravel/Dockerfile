FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

ENV DB_PATH=/data/vuln.db
EXPOSE 5000

# init_db() roda no __main__ antes do servidor subir.
CMD ["python", "app.py"]
