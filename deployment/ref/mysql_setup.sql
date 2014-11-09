/* sudo service mysqld start
 * sudo service mysqld status
 * sudo service mysqld stop
 *
 * sudo mysqld --ssl-ca="/home/jsmith/sem3/Security Lab/working/CA/ca_cert.pem" --ssl-cert="/home/jsmith/sem3/Security Lab/working/PKI/db_cert.pem" --ssl-key="/home/jsmith/sem3/Security Lab/working/PKI/db_key.pem" --user=root &>/dev/null &

 */

-- Create the CA user and require TLS authentication.
GRANT USAGE ON *.* TO 'ca'@'%';
DROP USER 'ca'@'%';
GRANT USAGE ON *.* TO 'ca'@'%'
	REQUIRE SUBJECT "/O=iMovies/OU=TLS Infrastructure/CN=Certificate Authority Server"
	AND ISSUER "/O=iMovies/OU=PKI Infrastructure/CN=Certificate Authority";

-- Create the database
DROP DATABASE IF EXISTS imovies;
CREATE DATABASE imovies;

-- Switch to the database and load it with user data
USE imovies;
SOURCE ref/imovies_users.dump;

-- Create the table holding user-cert assignments
DROP TABLE IF EXISTS user_certs;
CREATE TABLE user_certs (
	uid varchar(64) NOT NULL,
	serial varchar(40) NOT NULL, -- Maximum permitted serial number is 20 octects
	expired BOOLEAN NOT NULL DEFAULT FALSE,
	exp_date datetime NOT NULL,
	revoked BOOLEAN NOT NULL DEFAULT FALSE,
	subject TEXT NOT NULL,
	certificate LONGTEXT NOT NULL,
	private_key LONGTEXT NOT NULL,
	PRIMARY KEY(serial),
	FOREIGN KEY(uid) REFERENCES users(uid)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- Grant access priveleges
GRANT SELECT ON imovies.users TO 'ca'@'%';
GRANT SELECT, INSERT ON imovies.user_certs TO 'ca'@'%';
GRANT UPDATE (expired, revoked) ON imovies.user_certs TO 'ca'@'%';