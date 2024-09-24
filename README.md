# Project Setup Guide

This guide will help you set up a virtual environment and install the necessary packages to run the Flask project.

## Prerequisites

- Python 3.7 or higher should be installed on your machine.
- Ensure `pip` (Python's package installer) is installed. You can verify by running:

  ```bash
  pip --version
  ```

- Optionally, install `virtualenv` to create isolated environments for your Python projects. You can install it by running:

  ```bash
  pip install virtualenv
  ```

## Setup Instructions

### Step 1: Clone the repository

Clone the repository to your local machine using the following command:

```bash
git clone <repository-url>
```

Navigate to the project directory:

```bash
cd <project-directory>
```

### Step 2: Set up a virtual environment

To avoid conflicts with other Python projects, it's recommended to set up a virtual environment for this project.

1. **Create a virtual environment**:

   - For Windows:

     ```bash
     python -m venv venv
     ```

   - For macOS/Linux:

     ```bash
     python3 -m venv venv
     ```

2. **Activate the virtual environment**:

   - For Windows:

     ```bash
     .\venv\Scripts\activate
     ```

   - For macOS/Linux:

     ```bash
     source venv/bin/activate
     ```

   Once activated, your terminal prompt should change to indicate that you're working inside the virtual environment.

### Step 3: Install the required packages

Now that the virtual environment is activated, you can install the required packages using `pip`:

```bash
pip install -r requirements.txt
```

This will install all the necessary dependencies for the project as listed in the `requirements.txt` file.

### Database setup guide

- [Setup Database](https://www.geeksforgeeks.org/how-to-install-and-configure-mysql-on-arch-based-linux-distributionsmanjaro/)

### Step 4: Running the Flask Application

1. Set the `FLASK_APP` environment variable:

   - For Windows:

     ```bash
     set FLASK_APP=app.py
     ```

   - For macOS/Linux:

     ```bash
     export FLASK_APP=app.py
     ```

2. Run the Flask development server:

   ```bash
   flask --app app --debug run
   ```

This will start the Flask application, and you can access it by navigating to `http://127.0.0.1:5000/` in your web browser.

### Step 5: Deactivating the Virtual Environment

Once you're done working on the project, you can deactivate the virtual environment by running:

```bash
deactivate
```

## Additional Resources

- [Flask Documentation](https://flask.palletsprojects.com/)
- [WTForms Documentation](https://wtforms.readthedocs.io/)
