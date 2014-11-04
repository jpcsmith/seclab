/* sudo service mysqld start
 * sudo service mysqld status
 * sudo service mysqld stop
 */

-- Drop the user and tables if they exist
DROP USER 'ca'@'localhost';
DROP DATABASE IF EXISTS imovies;

-- Create the database and user
CREATE DATABASE imovies;

-- Switch to the database and load it with user data
USE imovies;
SOURCE imovies_users.dump;

-- Create the table holding user-cert assignments
DROP TABLE IF EXISTS user_certs;
CREATE TABLE user_certs (
	uid varchar(64) NOT NULL, 
	ca_serial varchar(40) NOT NULL, -- Maximum permitted serial number is 20 octects
	crt_serial varchar(40) NOT NULL,
	PRIMARY KEY(uid),
	UNIQUE(ca_serial, crt_serial),
	FOREIGN KEY(uid) REFERENCES users(uid) 
		ON DELETE RESTRICT -- Prevent deletion of a user if they have a cert issued
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- Grant access priveleges
CREATE USER 'ca'@'localhost';
GRANT SELECT ON imovies.users TO 'ca'@'localhost';
GRANT SELECT ON imovies.user_certs TO 'ca'@'localhost';



