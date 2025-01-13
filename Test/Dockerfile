FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip==24.3.1 setuptools==75.8.0

# Copy the requirements.txt file to the container
COPY requirements.txt .

# Install the required Python packages
RUN pip install --no-cache-dir -r requirements.txt

RUN pip install --no-cache-dir --upgrade dash flask

# Copy the Python script to the container
COPY firewallui.py .

# Define the command to run the application 
CMD ["python", "firewallui.py"]
