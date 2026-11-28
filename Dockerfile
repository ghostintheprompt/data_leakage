FROM python:3.12-slim

WORKDIR /app
COPY lab/requirements.txt /app/lab/requirements.txt
RUN pip install --no-cache-dir -r /app/lab/requirements.txt

COPY . /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

CMD ["python3", "-m", "unittest", "discover", "-s", "tests", "-v"]
