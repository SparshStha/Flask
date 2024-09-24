# project setup guide

this guide will help you set up a virtual environment and install the necessary packages to run the flask project.

## prerequisites

- python 3.7 or higher should be installed on your machine.
- ensure `pip` (python's package installer) is installed. you can verify by running:

  ```bash
  pip --version
  ```

- optionally, install `virtualenv` to create isolated environments for your python projects. you can install it by running:

  ```bash
  pip install virtualenv
  ```

## setup instructions

### step 1: clone the repository

clone the repository to your local machine using the following command:

```bash
git clone <repository-url>
```

navigate to the project directory:

```bash
cd <project-directory>
```

### step 2: set up a virtual environment

to avoid conflicts with other python projects, it's recommended to set up a virtual environment for this project.

1. **create a virtual environment**:

   - for windows:

     ```bash
     python -m venv venv
     ```

   - for macos/linux:

     ```bash
     python3 -m venv venv
     ```

2. **activate the virtual environment**:

   - for windows:

     ```bash
     .\venv\scripts\activate
     ```

   - for macos/linux:

     ```bash
     source venv/bin/activate
     ```

   once activated, your terminal prompt should change to indicate that you're working inside the virtual environment.

### step 3: install the required packages

now that the virtual environment is activated, you can install the required packages using `pip`:

```bash
pip install -r requirements.txt
```

this will install all the necessary dependencies for the project as listed in the `requirements.txt` file.

### database setup guide

- [setup database](https://www.geeksforgeeks.org/how-to-install-and-configure-mysql-on-arch-based-linux-distributionsmanjaro/)

### step 4: running the flask application

1. set the `flask_app` environment variable:

   - for windows:

     ```bash
     set flask_app=app.py
     ```

   - for macos/linux:

     ```bash
     export flask_app=app.py
     ```

2. run the flask development server:

   ```bash
   flask --app app --debug run
   ```

this will start the flask application, and you can access it by navigating to `http://127.0.0.1:5000/` in your web browser.

### step 5: deactivating the virtual environment

once you're done working on the project, you can deactivate the virtual environment by running:

```bash
deactivate
```

## additional resources

- [flask documentation](https://flask.palletsprojects.com/)
- [wtforms documentation](https://wtforms.readthedocs.io/)

# project setup guide

this guide will help you set up a virtual environment, install the necessary packages, and run the flask project using sqlalchemy and flask-migrate for database migrations.

## prerequisites

- **python 3.7 or higher** should be installed on your machine.
- ensure **`pip`** (python's package installer) is installed. you can verify by running:

  ```bash
  pip --version
  ```

- optionally, install **`virtualenv`** to create isolated environments for your python projects. you can install it by running:

  ```bash
  pip install virtualenv
  ```

- **mysql server** installed and running on your local machine.
  - ensure you have the credentials (username and password) to access your mysql server.
  - [download mysql server](https://dev.mysql.com/downloads/mysql/)
- **mysql client tools** (optional but recommended) for managing your mysql databases.

## setup instructions

### step 1: clone the repository

clone the repository to your local machine using the following command:

```bash
git clone <repository-url>
```

replace `<repository-url>` with the actual url of your repository.

navigate to the project directory:

```bash
cd <project-directory>
```

### step 2: set up a virtual environment

to avoid conflicts with other python projects, it's recommended to set up a virtual environment for this project.

1. **create a virtual environment**:

   - for windows:

     ```bash
     python -m venv env
     ```

   - for macos/linux:

     ```bash
     python3 -m venv env
     ```

2. **activate the virtual environment**:

   - for windows:

     ```bash
     env\scripts\activate
     ```

   - for macos/linux:

     ```bash
     source env/bin/activate
     ```

   once activated, your terminal prompt should change to indicate that you're working inside the virtual environment.

### step 3: install the required packages

now that the virtual environment is activated, install the required packages using `pip`:

```bash
pip install -r requirements.txt
```

this will install all the necessary dependencies for the project as listed in the `requirements.txt` file.

### step 4: configure the database

#### 1. create the database

open your mysql client and create a new database named `acs` (or use a different name and update your configuration accordingly):

```sql
create database acs;
```

#### 2. update database credentials

ensure that the database credentials in your `app.py` file match your mysql server's username and password:

```python
app.config['sqlalchemy_database_uri'] = 'mysql+pymysql://<username>:<password>@localhost/acs'
```

replace `<username>` and `<password>` with your mysql username and password.

**security tip**: for better security, consider using environment variables or a `.env` file to store sensitive information like database credentials.

### step 5: initialize database migrations

with sqlalchemy and flask-migrate, you need to set up the migration repository and apply migrations.

#### 1. initialize the migration environment

in the project directory, run:

```bash
flask db init
```

this will create a `migrations` directory in your project.

#### 2. stamp the current database

if your database already exists with the required tables (e.g., from a previous setup), you need to stamp the current state of the database schema:

```bash
flask db stamp head
```

#### 3. generate migration scripts

whenever you make changes to your models, generate a migration script:

```bash
flask db migrate -m "initial migration."
```

#### 4. apply migrations

apply the migrations to the database:

```bash
flask db upgrade
```

this will create the necessary tables as defined in your models if they don't already exist.

### step 6: run the flask application

#### 1. set the `flask_app` environment variable

- for windows:

  ```bash
  set flask_app=app.py
  ```

- for macos/linux:

  ```bash
  export flask_app=app.py
  ```

#### 2. (optional) enable debug mode

to enable debug mode (which provides detailed error pages and auto-reloading):

- for windows:

  ```bash
  set flask_debug=1
  ```

- for macos/linux:

  ```bash
  export flask_debug=1
  ```

#### 3. run the flask development server

start the flask application:

```bash
flask run
```

by default, the application will be accessible at `http://127.0.0.1:5000/`.

### step 7: deactivate the virtual environment

once you're done working on the project, deactivate the virtual environment by running:

```bash
deactivate
```

## database setup guide

if you need help setting up mysql on your system, refer to this guide:

- [how to install and configure mysql on arch-based linux distributions (manjaro)](https://www.geeksforgeeks.org/how-to-install-and-configure-mysql-on-arch-based-linux-distributionsmanjaro/)

for other operating systems, you can find installation guides on the official mysql website or other reputable sources.

## additional resources

- [flask documentation](https://flask.palletsprojects.com/)
- [flask-sqlalchemy documentation](https://flask-sqlalchemy.palletsprojects.com/)
- [flask-migrate documentation](https://flask-migrate.readthedocs.io/)
- [wtforms documentation](https://wtforms.readthedocs.io/)
- [sqlalchemy documentation](https://docs.sqlalchemy.org/)
- [alembic documentation](https://alembic.sqlalchemy.org/)

## notes and tips

### using environment variables for configuration

for security and flexibility, it's a good practice to use environment variables for configuration settings like database credentials.

**example using `python-dotenv`:**

1. **install `python-dotenv`:**

   ```bash
   pip install python-dotenv
   ```

2. **create a `.env` file** in your project directory:

   ```
   db_username=your_username
   db_password=your_password
   ```

3. **update `app.py` to load environment variables:**

   ```python
   from dotenv import load_dotenv
   import os

   load_dotenv()

   app.config['sqlalchemy_database_uri'] = f"mysql+pymysql://{os.getenv('db_username')}:{os.getenv('db_password')}@localhost/acs"
   ```

### managing migrations

- **Initialize Migrations:**

  ```bash
  flask db init
  ```

- **Generate a Migration:**

  ```bash
  flask db migrate -m "Description of changes"
  ```

- **Apply Migrations:**

  ```bash
  flask db upgrade
  ```

- **Rollback Migrations:**

  ```bash
  flask db downgrade
  ```

### Handling Model Changes

Whenever you make changes to your models (e.g., adding a new field), follow these steps:

1. **Generate a new migration script:**

   ```bash
   flask db migrate -m "Describe the changes"
   ```

2. **Review the Migration Script (Optional):**

   Check the migration script in the `migrations/versions` directory to ensure it's correct.

3. **Apply the migration:**

   ```bash
   flask db upgrade
   ```
