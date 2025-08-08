
FROM python:3.11-slim
WORKDIR /app

# Copy only necessary files
COPY requirements.txt ./
COPY main.py ingestor.py gpt_executor.py readme.md ./
COPY docs ./docs

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose API port
EXPOSE 8000

# Set environment variables for MongoDB connection (can be overridden at runtime)
ENV MONGO_URI=mongodb://host.docker.internal:27017/
ENV DB_NAME=mitre_attack

# Default command to run the FastAPI app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
