<?php
require_once 'config/database.php';
if (isLoggedIn()) { header('Location: dashboard.php'); exit; }

$success = $error = '';
if ($_POST) {
    $username = trim($_POST['username']);
    $email    = trim($_POST['email']);
    $password = $_POST['password'];
    $role     = in_array($_POST['role'], ['manager','staff']) ? $_POST['role'] : 'staff';

    if (strlen($password) < 6) {
        $error = 'Password must be at least 6 characters.';
    } else {
        try {
            $is_first = ($role === 'staff') ? 1 : 0;
            $stmt = $pdo->prepare("INSERT INTO users (username, email, password, role, is_first_login) VALUES (?, ?, ?, ?, ?)");
            $stmt->execute([$username, $email, password_hash($password, PASSWORD_DEFAULT), $role, $is_first]);
            $success = 'Account created! You can now login.';
        } catch (Exception $e) {
            $error = 'Username or email already exists.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - DyeStock</title>
    <link rel="stylesheet" href="assets/style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .role-cards { display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-top:6px; }
        .role-card  { border:2px solid #e2e8f0; border-radius:10px; padding:14px; cursor:pointer; transition:all 0.2s; }
        .role-card:hover { border-color:#3b82f6; }
        .role-card input[type=radio] { display:none; }
        .role-card.selected { border-color:#3b82f6; background:#eff6ff; }
        .role-card .rc-icon { font-size:1.6rem; margin-bottom:6px; display:block; }
        .role-card .rc-title { font-weight:700; font-size:0.92rem; color:#0f172a; }
        .role-card .rc-desc  { font-size:0.78rem; color:#64748b; margin-top:3px; }
    </style>
</head>
<body class="login-page">
    <div class="login-container" style="max-width:460px;">
        <div class="login-card">
            <div class="logo">
                <h1><i class="fas fa-palette"></i> DyeStock</h1>
                <p>Create New Account</p>
            </div>

            <?php if ($error):   ?><div class="alert error">  ❌ <?php echo htmlspecialchars($error);   ?></div><?php endif; ?>
            <?php if ($success): ?><div class="alert success">✅ <?php echo htmlspecialchars($success); ?></div><?php endif; ?>

            <form method="POST" id="regForm">
                <div class="form-group">
                    <label><i class="fas fa-user"></i> Username</label>
                    <input type="text" name="username" required value="<?php echo htmlspecialchars($_POST['username']??''); ?>">
                </div>
                <div class="form-group">
                    <label><i class="fas fa-envelope"></i> Email</label>
                    <input type="email" name="email" required value="<?php echo htmlspecialchars($_POST['email']??''); ?>">
                </div>
                <div class="form-group">
                    <label><i class="fas fa-lock"></i> Password</label>
                    <input type="password" name="password" required placeholder="Min 6 characters">
                </div>

                <div class="form-group">
                    <label><i class="fas fa-id-badge"></i> Role</label>
                    <div class="role-cards">
                        <label class="role-card <?php echo (($_POST['role']??'staff')==='manager')?'selected':''; ?>" id="card-manager">
                            <input type="radio" name="role" value="manager" <?php echo (($_POST['role']??'')==='manager')?'checked':''; ?>>
                            <span class="rc-icon">👔</span>
                            <div class="rc-title">Inventory Manager</div>
                            <div class="rc-desc">Full access — manage products, receipts, deliveries, adjustments & reports</div>
                        </label>
                        <label class="role-card <?php echo (($_POST['role']??'staff')==='staff')?'selected':''; ?>" id="card-staff">
                            <input type="radio" name="role" value="staff" <?php echo (($_POST['role']??'staff')==='staff')?'checked':''; ?>>
                            <span class="rc-icon">🏗️</span>
                            <div class="rc-title">Warehouse Staff</div>
                            <div class="rc-desc">Limited access — receive stock, dispatch, transfers & shelving</div>
                        </label>
                    </div>
                </div>

                <button type="submit" class="btn-primary" style="width:100%;justify-content:center;padding:12px;font-size:1rem;margin-top:8px;">
                    ✅ Create Account
                </button>
            </form>
            <p style="text-align:center;margin-top:20px;color:#94a3b8;font-size:0.88rem;">
                Already have an account? <a href="login.php" style="color:#3b82f6;">Login</a>
            </p>
        </div>
    </div>
    <script>
        // Highlight selected role card
        document.querySelectorAll('.role-card input[type=radio]').forEach(radio => {
            radio.addEventListener('change', () => {
                document.querySelectorAll('.role-card').forEach(c => c.classList.remove('selected'));
                radio.closest('.role-card').classList.add('selected');
            });
        });
    </script>
</body>
</html>