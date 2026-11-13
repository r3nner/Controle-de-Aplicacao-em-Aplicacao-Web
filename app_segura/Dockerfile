FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt gunicorn==23.0.0
COPY . .

ENV DB_PATH=/data/segura.db
# Em HTTP de laboratorio o cookie Secure impediria o envio pelo navegador;
# por isso o demo roda com Secure=false. Em producao: true + HTTPS.
ENV SESSION_COOKIE_SECURE=false
EXPOSE 5000

# Semeia o usuario 'alvo' (idempotente) e sobe o servidor.
CMD ["sh", "-c", "python seed.py && gunicorn -b 0.0.0.0:5000 app:app"]
