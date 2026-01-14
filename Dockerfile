FROM python:3.11-slim

WORKDIR /app

COPY ollama-honeypot.py ollama-honeypot.conf ollama-honeypot.responses ./

EXPOSE 11434

CMD ["python", "ollama-honeypot.py"]
