# Use an official lightweight Python image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Copy the dependencies file and install them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code
COPY . .

# Create data directory for persistent storage
RUN mkdir -p /data

# Expose the port the app runs on
EXPOSE 8000

# Command to run the application using Gunicorn (a production-ready server)
CMD ["gunicorn", "--workers", "1", "--bind", "0.0.0.0:8000", "app:app"]
