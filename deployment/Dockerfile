# Using a slim version of Python to keep the image small
FROM python:3.11-slim

# Set the working directory inside the container
WORKDIR /app

# Step 1: Copy only the requirements first
# This allows Docker to cache the 'pip install' layer unless requirements.txt changes
COPY requirements.txt .

# Step 2: Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Step 3: Copy the rest of the scanner source code
# We copy the 'scanner' folder into the container
COPY scanner/ ./scanner/

# Create a directory for the reports to be saved
RUN mkdir -p /app/reports

# Set the environment variable to ensure Python output is sent straight to terminal
ENV PYTHONUNBUFFERED=1

# The entrypoint tells Docker what command to run by default
# Dev B will mount the host files to /data and we scan that path
ENTRYPOINT ["python", "scanner/main.py"]
CMD ["/data"]