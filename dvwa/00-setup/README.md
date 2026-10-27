# Lab setup

How I run DVWA for these writeups. Two machines on my home network.

## Topology

- Attacker: CachyOS (Arch), where I run exploit.py and the browser.
- Target: a home server running Ubuntu Server at 192.168.8.180.
- DVWA is reached from the attacker at http://192.168.8.180/DVWA.

## DVWA install (manual LAMP on Ubuntu Server)

Installed by hand on the Ubuntu box, not in Docker.

1. Install the stack:

       sudo apt update
       sudo apt install apache2 mariadb-server php php-mysqli php-gd git

2. Clone DVWA into the web root:

       sudo git clone https://github.com/digininja/DVWA /var/www/html/DVWA

3. Create the config and set the database credentials:

       cd /var/www/html/DVWA/config
       sudo cp config.inc.php.dist config.inc.php
       # edit config.inc.php: set db_user and db_password

4. Create the database and user in MariaDB:

       sudo mysql
       CREATE DATABASE dvwa;
       CREATE USER 'dvwa'@'localhost' IDENTIFIED BY '<password>';
       GRANT ALL ON dvwa.* TO 'dvwa'@'localhost';
       FLUSH PRIVILEGES;

5. Let Apache write the folders DVWA NEEDS:

       sudo chown -R www-data:www-data /var/www/html/DVWA

6. Open http://192.168.8.180/DVWA/setup.php and click Create / Reset Database.

## Using it

- Log in with the default admin / password.
- Set the level under DVWA Security before each writeup. It's stored in the
  security cookie and the session, so it has to match the writeup you're reproducing.

## Notes

- Default creds: admin / password.
- The database has to be initialised once from setup.php or nothing works.
- For the File Inclusion module later, allow_url_include must be On in php.ini.
- The server is on my LAN only, not exposed to the internet.