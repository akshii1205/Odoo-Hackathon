-- DyeStock - Full Database Setup
CREATE DATABASE IF NOT EXISTS dyestock;
USE dyestock;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) UNIQUE,
    password VARCHAR(255) NOT NULL DEFAULT 'admin',
    role ENUM('manager','staff','viewer') DEFAULT 'staff',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Categories table
CREATE TABLE IF NOT EXISTS categories (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Warehouses table
CREATE TABLE IF NOT EXISTS warehouses (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    location VARCHAR(200),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Suppliers table
CREATE TABLE IF NOT EXISTS suppliers (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(100) NOT NULL,
    contact VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Products table
CREATE TABLE IF NOT EXISTS products (
    id INT PRIMARY KEY AUTO_INCREMENT,
    dye_name VARCHAR(150) NOT NULL,
    sku VARCHAR(50) NOT NULL UNIQUE,
    category_id INT,
    unit VARCHAR(10) DEFAULT 'kg',
    current_stock DECIMAL(10,2) DEFAULT 0,
    min_stock_level DECIMAL(10,2) DEFAULT 10,
    warehouse_id INT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES categories(id),
    FOREIGN KEY (warehouse_id) REFERENCES warehouses(id)
);

-- Inventory movements table
CREATE TABLE IF NOT EXISTS inventory_movements (
    id INT PRIMARY KEY AUTO_INCREMENT,
    product_id INT NOT NULL,
    movement_type ENUM('receipt','delivery','transfer_in','transfer_out','adjustment_in','adjustment_out') NOT NULL,
    quantity DECIMAL(10,2) NOT NULL,
    company_name VARCHAR(150) NULL,
    reference_no VARCHAR(50),
    notes TEXT,
    balance_after DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by INT,
    FOREIGN KEY (product_id) REFERENCES products(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

-- OTP table
CREATE TABLE IF NOT EXISTS otp_codes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    expires_at DATETIME NOT NULL,
    used TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Sample data
INSERT IGNORE INTO users (id, username, email, password, role) VALUES
(1, 'admin', 'admin@dyestock.com', 'admin', 'manager');

INSERT IGNORE INTO categories (name) VALUES
('Reactive Dyes'), ('Acid Dyes'), ('Direct Dyes'), ('Disperse Dyes'), ('Vat Dyes');

INSERT IGNORE INTO warehouses (id, name, location) VALUES
(1, 'Main Warehouse', 'Block A, Ahmedabad'),
(2, 'Secondary Warehouse', 'Block B, Ahmedabad');

INSERT IGNORE INTO suppliers (name, contact) VALUES
('ColorChem Ltd', 'contact@colorchem.com'),
('DyeMasters Inc', 'info@dyemasters.com');

INSERT IGNORE INTO products (dye_name, sku, category_id, unit, current_stock, min_stock_level, warehouse_id) VALUES
('Reactive Blue 19', 'RB19-001', 1, 'kg', 150.50, 20, 1),
('Acid Red 88',      'AR88-002', 2, 'kg',  75.25, 15, 1),
('Direct Black 38',  'DB38-003', 3, 'kg', 200.00, 25, 2);

-- Fix: Add 'delivery' to movement_type ENUM
ALTER TABLE inventory_movements
MODIFY COLUMN movement_type
ENUM('receipt','delivery','transfer_in','transfer_out','adjustment_in','adjustment_out') NOT NULL;

-- Fix: Add company_name if not exists
ALTER TABLE inventory_movements
ADD COLUMN IF NOT EXISTS company_name VARCHAR(150) NULL AFTER quantity;

-- Fix: Add OTP table if not exists
CREATE TABLE IF NOT EXISTS otp_codes (
    id INT PRIMARY KEY AUTO_INCREMENT,
    user_id INT NOT NULL,
    otp_code VARCHAR(6) NOT NULL,
    expires_at DATETIME NOT NULL,
    used TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Add is_first_login column to users (for staff first-login OTP)
ALTER TABLE users
ADD COLUMN IF NOT EXISTS is_first_login TINYINT(1) DEFAULT 0 AFTER role;

-- Add purpose column to otp_codes
ALTER TABLE otp_codes
ADD COLUMN IF NOT EXISTS purpose ENUM('first_login','forgot_password') DEFAULT 'first_login' AFTER used;