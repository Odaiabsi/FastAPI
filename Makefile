# Placeholder for project name
PROJECT_NAME = my-fastapi-app

# Python version
PYTHON_VERSION = 3.9

# Virtual environment management
venv:
    python$(PYTHON_VERSION) -m venv venv

# Install dependencies
install:
    pip install -r requirements.txt

# Run the application
run:
    uvicorn $(PROJECT_NAME).main:app --reload

# Run tests (assuming you have pytest set up)
test:
    pytest

# Lint code (assuming you have flake8 installed)
lint:
    flake8 .
