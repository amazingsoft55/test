-- Veritabanı oluşturma
CREATE DATABASE IF NOT EXISTS auth_db;
USE auth_db;

-- Kullanıcı tablosu
CREATE TABLE IF NOT EXISTS users (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  email VARCHAR(100) NOT NULL UNIQUE,
  password VARCHAR(255) NOT NULL,
  enabled BOOLEAN DEFAULT TRUE,
  mfa_enabled BOOLEAN DEFAULT FALSE,
  mfa_secret VARCHAR(255),
  login_attempts INT DEFAULT 0,
  last_login_attempt TIMESTAMP,
  account_locked BOOLEAN DEFAULT FALSE,
  account_locked_until TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Rol tablosu
CREATE TABLE IF NOT EXISTS roles (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(20) NOT NULL UNIQUE
);

-- Kullanıcı-Rol ilişki tablosu
CREATE TABLE IF NOT EXISTS user_roles (
  user_id BIGINT NOT NULL,
  role_id BIGINT NOT NULL,
  PRIMARY KEY (user_id, role_id),
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (role_id) REFERENCES roles(id)
);

-- Şifre geçmişi tablosu
CREATE TABLE IF NOT EXISTS password_history (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT NOT NULL,
  password VARCHAR(255) NOT NULL,
  change_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Güvenlik olay günlüğü tablosu
CREATE TABLE IF NOT EXISTS security_audit_log (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  event_type VARCHAR(50) NOT NULL,
  username VARCHAR(50),
  ip_address VARCHAR(50),
  event_data JSON,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- İptal edilmiş token tablosu
CREATE TABLE IF NOT EXISTS blacklisted_tokens (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  token_hash VARCHAR(255) NOT NULL UNIQUE,
  expiry_date TIMESTAMP NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Temel rol ekleyelim
INSERT INTO roles (name) VALUES ('ADMIN'), ('USER') ON DUPLICATE KEY UPDATE name = VALUES(name); 