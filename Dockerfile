FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN python run.py all --profile full
EXPOSE 8080
CMD ["python", "run.py", "serve", "--profile", "full", "--port", "8080", "--host", "0.0.0.0"]
