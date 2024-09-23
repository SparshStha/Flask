Extract the zip file, then install XAMPP and VsCode.
After installing XAMPP, we need to start MySQL and Apache servers.
Then go to http://localhost/phpmyadmin/
Create the database where user information is stored. To create it, you can create it manually or use the following code:
 
CREATE DATABASE IF NOT EXISTS mydatabase;
 
CREATE TABLE users (
    id INT(11) NOT NULL AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(200) NOT NULL,
    password VARCHAR(200) NOT NULL,
    failed_attempts INT(11) NOT NULL DEFAULT 0,
    lockout_time TIMESTAMP NULL DEFAULT NULL,
    PRIMARY KEY (id)
);

 
Note: Without creating this, if you try to run the code, it will show an error message. Make sure that the database is created properly.
 
After that, open the code using VsCode, and if this thing is not installed on your system, then you need to install it; otherwise, the code won't run. 
Flask ("pip install flask")
bcrypt ("pip install bcrypt")
sys ("pip install sys")
wtforms ("pip install wtforms")
flask_wtf ("pip install Flask_WTF") 
MySQL ("pip install mysql")
Note: "Install this using VsCode Terminal"
 
Installation is done, now time to run the code. To run the code, we need to again go to the VsCode Terminal and type: python :\app.py
Note: "Make sure that in XAMPP MySQL and Apache are running; if these two aren't running and you try to run the code, the code won't run."
 
After that, open any browser and type 127.0.0.1:500
I hope using this following steps code will run successfully.
