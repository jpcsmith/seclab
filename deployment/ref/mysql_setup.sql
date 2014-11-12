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
	AND ISSUER "/O=iMovies/OU=PKI Infrastructure/CN=iMovies Certificate Authority";

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
	rev_date datetime,
	subject TEXT NOT NULL,
	PRIMARY KEY(serial),
	FOREIGN KEY(uid) REFERENCES users(uid),
	FOREIGN KEY(serial) REFERENCES cert_archive(serial)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- Create the table for permissions
DROP TABLE IF EXISTS user_roles;
CREATE TABLE user_roles (
	uid varchar(64) NOT NULL PRIMARY KEY,
	is_ca_admin boolean NOT NULL DEFAULT FALSE,
	FOREIGN KEY(uid) REFERENCES users(uid)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- Create the table for holding the cert archive details
DROP TABLE IF EXISTS cert_archive;
CREATE TABLE cert_archive (
	serial varchar(40) NOT NULL,
	certificate LONGTEXT NOT NULL,
	encrypted_priv_key LONGTEXT NOT NULL, -- AES256CBC encrypted and in b64
	salt TEXT NOT NULL,
	encrypted_sym_key TEXT NOT NULL, 
	encrypted_iv TEXT NOT NULL,
	PRIMARY KEY(serial)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;

-- Create the table for holding the crl details
DROP TABLE IF EXISTS crl_list;
CREATE TABLE crl_list (
	id mediumint NOT NULL AUTO_INCREMENT,
	gen_date datetime NOT NULL,
	crl LONGTEXT NOT NULL,
	PRIMARY KEY (id)
) ENGINE=MyISAM DEFAULT CHARSET=latin1;


DELIMITER //
CREATE PROCEDURE imovies.check_login(IN uid varchar(64), IN pHash varchar(64),
	OUT isValid boolean)
SQL SECURITY DEFINER
BEGIN
	SELECT EXISTS(SELECT 1 FROM users WHERE users.uid=uid AND users.pwd=pHash)
		INTO isValid;
END //

-- Returns 1(TRUE), 0(FALSE) or NULL(serial doesnt exist)
CREATE PROCEDURE imovies.is_admin(IN serial varchar(40), OUT isAdmin boolean)
BEGIN
	SELECT COALESCE(user_roles.is_ca_admin, FALSE) FROM user_certs 
		LEFT JOIN user_roles ON user_certs.uid = user_roles.uid WHERE user_certs.serial = serial
		INTO  isAdmin;
END //
DELIMITER ;

-- INSERT INTO user_certs(uid, serial, exp_date, subject) VALUES 
--	('fu', 'AA', UTC_TIMESTAMP(), 'testsubAA'),
--	('db', 'BB', UTC_TIMESTAMP(), 'testsubBB');
--INSERT INTO user_roles(uid, is_ca_admin) VALUE ('fu', TRUE);

-- Grant access priveleges
GRANT SELECT (uid, lastname, firstname, email) ON imovies.users TO 'ca'@'%';
GRANT SELECT, INSERT ON imovies.user_certs TO 'ca'@'%';
GRANT UPDATE (expired, revoked, rev_date) ON imovies.user_certs TO 'ca'@'%';
GRANT INSERT ON imovies.cert_archive TO 'ca'@'%';
GRANT INSERT ON imovies.crl_list TO 'ca'@'%';
GRANT EXECUTE ON PROCEDURE imovies.check_login TO 'ca'@'%';
GRANT EXECUTE ON PROCEDURE imovies.is_admin TO 'ca'@'%';
