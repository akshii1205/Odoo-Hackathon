# Odoo-Hackathon
# 🧵 DyeStock — Textile Dye Inventory Management System

DyeStock is a full-featured web-based inventory management system built specifically for textile dye businesses. It allows managers and warehouse staff to track incoming and outgoing dye stock, manage warehouses, record deliveries to companies, transfer stock between locations, and generate a complete transaction history — all from a clean, modern UI.

---

## 📸 Screenshots

| Login | Dashboard (Manager) | Dashboard (Staff) |
|-------|--------------------|--------------------|
| Dark themed login with OTP support | Full stats, quick actions & recent activity | Role-limited warehouse task view |

---

## ✨ Features

### 🔐 Authentication & Security
- Secure login with **bcrypt password hashing**
- **Role-based access control** — Manager and Warehouse Staff roles
- **OTP-based password reset** via email (forgot password flow)
- Session-based authentication with auto-redirect

### 👔 Inventory Manager — Full Access
- **Dashboard** — live stats (total products, low stock alerts, today's movements, warehouses)
- **Products** — add products with SKU, category, unit, min stock level, warehouse assignment
- **Search & Filter** — search by product name / SKU, filter by warehouse
- **Receipts** — record incoming stock with supplier name, invoice reference, notes
- **Deliveries** — dispatch stock to companies with company name, invoice number
- **Transfers** — move stock between warehouses
- **Adjustments** — correct stock discrepancies (damage, spillage, theft, physical count)
- **History** — full transaction ledger with filters by type, product, and date

### 🏗️ Warehouse Staff — Limited Access
- **Dashboard** — simplified view with warehouse task cards
- **Receive Stock** — record incoming dye deliveries
- **Dispatch / Picking** — record outgoing stock to companies
- **Transfers / Shelving** — move dyes between warehouse locations

### 🎨 UI & Design
- Dark themed login, register, forgot password, OTP verify, and reset password pages
- Blue gradient sidebar with role badge (Manager/Staff)
- Responsive stat cards, quick action cards, and data tables
- Color-coded movement type badges (receipt, delivery, transfer, adjustment)
- Low stock alerts highlighted in red

---

## 🗂️ Project Structure

```
DyeStock/
├── index.php                  # Entry point — redirects based on session
├── login.php                  # Login page (dark UI)
├── logout.php                 # Session destroy & redirect
├── register.php               # Create new account with role selection
├── forgot_password.php        # Enter email to receive OTP
├── otp_verify.php             # Enter 6-digit OTP code
├── reset_password.php         # Set new password after OTP verification
│
├── dashboard.php              # Role-based dashboard
├── products.php               # Product management (Manager only)
├── receipts.php               # Incoming stock
├── deliveries.php             # Outgoing stock with company name
├── transfers.php              # Stock transfers between warehouses
├── adjustment.php             # Stock adjustments (Manager only)
├── history.php                # Full transaction ledger (Manager only)
│
├── assets/
│   ├── style.css              # Main stylesheet
│   └── script.js              # Modal open/close JS
│
├── config/
│   ├── database.php           # PDO connection + auth helper functions
│   └── mail.php               # Email configuration + sendOTPEmail()
│
├── includes/
│   └── sidebar.php            # Role-aware navigation sidebar
│
└── database.sql               # Full database schema + sample data
```

---

## 🗄️ Database Schema

| Table | Description |
|-------|-------------|
| `users` | Stores all users with username, email, hashed password, role |
| `products` | Dye products with SKU, stock level, category, warehouse |
| `categories` | Dye categories (Reactive, Acid, Direct, Disperse, Vat) |
| `warehouses` | Warehouse locations |
| `suppliers` | Supplier records |
| `inventory_movements` | All stock movements (receipts, deliveries, transfers, adjustments) |
| `otp_codes` | OTP codes for password reset with expiry |

---

## ⚙️ Installation

### Prerequisites
- **XAMPP** (or any PHP + MySQL stack)
- PHP 7.4 or higher
- MySQL 5.7 or higher

### Step 1 — Clone or Download

```bash
git clone https://github.com/yourusername/DyeStock.git
```

Or download the ZIP and extract it.

### Step 2 — Place in Web Root

Copy the `DyeStock` folder into your XAMPP `htdocs` directory:

```
C:\xampp\htdocs\DyeStock\
```

### Step 3 — Import the Database

1. Start **Apache** and **MySQL** in XAMPP Control Panel
2. Open **phpMyAdmin** → `http://localhost/phpmyadmin`
3. Click **Import** → choose `database.sql` from the project folder
4. Click **Go**

### Step 4 — Configure Database Connection

Open `config/database.php` and update if needed:

```php
$host     = 'localhost';
$dbname   = 'dyestock';
$username = 'root';
$password = '';        // Leave blank for default XAMPP
```

### Step 5 — Open in Browser

```
http://localhost/DyeStock/
```

---

## 🔑 Default Login Credentials

| Role | Username | Password |
|------|----------|----------|
| Inventory Manager | `admin` | `admin` |

> ⚠️ Change the default password after first login for security.

To create a **Warehouse Staff** account, go to `register.php` and select the **Warehouse Staff** role.

---

## 📧 Email Configuration (OTP)

To enable OTP email for password reset, open `config/mail.php` and update:

```php
define('SMTP_FROM',      'your@gmail.com');
define('SMTP_FROM_NAME', 'DyeStock');
```

Then configure PHP's `mail()` in `php.ini` (for XAMPP):

```ini
[mail function]
SMTP=smtp.gmail.com
smtp_port=587
sendmail_from=your@gmail.com
```

> **Dev Mode:** If email is not configured, the OTP will be displayed directly on the screen so you can still test the flow without email setup.

---

## 🔒 Role Permissions

| Feature | Manager | Staff |
|---------|---------|-------|
| Dashboard | ✅ Full | ✅ Limited |
| Products (view & add) | ✅ | ❌ |
| Receipts | ✅ | ✅ |
| Deliveries | ✅ | ✅ |
| Transfers | ✅ | ✅ |
| Adjustments | ✅ | ❌ |
| History / Ledger | ✅ | ❌ |
| Register new users | ✅ | ❌ |

---

## 📦 Movement Types

| Type | Description | Who |
|------|-------------|-----|
| `receipt` | Stock received from supplier | Manager / Staff |
| `delivery` | Stock dispatched to a company | Manager / Staff |
| `transfer_in` | Stock moved into a warehouse | Manager / Staff |
| `transfer_out` | Stock moved out of a warehouse | Manager / Staff |
| `adjustment_in` | Manual stock increase | Manager only |
| `adjustment_out` | Manual stock decrease | Manager only |

---

## 🔄 Forgot Password Flow

```
1. Click "Forgot password?" on login page
2. Enter registered email address
3. Receive 6-digit OTP (valid 10 minutes)
4. Enter OTP on otp_verify.php
5. Set new password on reset_password.php
6. Login with new password
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | PHP 8+ (no framework) |
| Database | MySQL via PDO |
| Frontend | HTML5, CSS3, Vanilla JS |
| Icons | Font Awesome 6 |
| Fonts | Inter (Google Fonts) |
| Server | Apache (XAMPP) |

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch — `git checkout -b feature/your-feature`
3. Commit your changes — `git commit -m 'Add your feature'`
4. Push to the branch — `git push origin feature/your-feature`
5. Open a Pull Request

---

## 📄 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

## 👨‍💻 Author

Built with ❤️ for textile inventory management.

> Made in Ahmedabad, Gujarat 🇮🇳
