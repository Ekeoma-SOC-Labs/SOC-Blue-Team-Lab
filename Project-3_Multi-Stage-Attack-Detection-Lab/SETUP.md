# Setup Instructions for Project 3: Multi-Stage Attack Detection Lab

## Prerequisites
Before you begin the setup process, ensure you have the following prerequisites installed on your system:
- Python 3.8 or higher
- Docker
- Docker Compose
- Git

## Step 1: Clone the Repository
First, clone the repository to your local machine using the following command:

```bash
git clone https://github.com/Ekeoma-SOC-Labs/SOC-Blue-Team-Lab.git
```

Navigate to the project directory:

```bash
cd SOC-Blue-Team-Lab/Project-3_Multi-Stage-Attack-Detection-Lab
```

## Step 2: Set Up the Environment
Set up your virtual environment to manage dependencies:

```bash
python -m venv venv
source venv/bin/activate  # On Windows use `venv\Scripts\activate`
```

Install the required Python packages:

```bash
pip install -r requirements.txt
```

## Step 3: Configure Docker
Ensure Docker is running on your machine. You can test this by executing:

```bash
docker --version
```

## Step 4: Build Docker Containers
Use Docker Compose to build and run the containers:

```bash
docker-compose up --build
```

## Step 5: Access the Application
After the build process completes, you can access the application in your web browser at:

```
http://localhost:5000
```

## Troubleshooting
If you encounter issues during the setup, consider the following:
- Ensure you have sufficient permissions to run Docker.
- Check for any typos in the commands.

## Conclusion
You should now have the Multi-Stage Attack Detection Lab set up and running! Refer to the documentation for more specific usage instructions.
