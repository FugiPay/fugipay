FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY fraud_detection.py .

ENV MONGO_URI=mongodb+srv://KHAH-YAH:01H0EwNnhMYW8zpO@cluster0.1ap41.mongodb.net/Zangena?retryWrites=true&w=majority
ENV FLASK_ENV=production

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "fraud_detection:app"]