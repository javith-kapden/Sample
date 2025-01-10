
# Use an official Python runtime as a base image 
FROM python:3.9-slim

# Set the working directory inside the container 
WORKDIR /Test

RUN pip install --no-cache-dir --upgrade pip==23.2.1 setuptools==65.5.1

# Copy the requirements.txt file to the container
COPY requirements.txt .

# Install the required Python packages
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Python script to the container
COPY firewallui.py .

# Define the command to run the application 
CMD ["python", "firewallui.py"]
