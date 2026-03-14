<?php
require_once 'config/database.php';
if (isLoggedIn()) { header('Location: dashboard.php'); exit; }

// Must have a valid reset session
if (empty($_SESSION['reset_user_id'])) {
    header('Location: login.php'); exit;
}

$error = $success = '';
$user_id = $_SESSION['reset_user_id'];

if ($_POST && isset($_POST['reset_pass'])) {
    $new_pass     = $_POST['new_password'];
    $confirm_pass = $_POST['confirm_password'];

    if (strlen($new_pass) < 6) {
        $error = 'Password must be at least 6 characters.';
    } elseif ($new_pass !== $confirm_pass) {
        $error = 'Passwords do not match.';
    } else {
        $hashed = password_hash($new_pass, PASSWORD_DEFAULT);
        $pdo->prepare("UPDATE users SET password = ? WHERE id = ?")->execute([$hashed, $user_id]);
        unset($_SESSION['reset_user_id']);
        $success = 'Password reset successfully! You can now login.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password - DyeStock</title>
    <link rel="stylesheet" href="assets/style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="login-page">
    <div class="login-container">
        <div class="login-card">
            <div class="logo">
                <h1><i class="fas fa-lock"></i> Reset Password</h1>
                <p>Set your new password</p>
            </div>

            <?php if ($error):   ?><div class="alert error">  <i class="fas fa-exclamation-circle"></i> <?php echo $error;   ?></div><?php endif; ?>
            <?php if ($success): ?>
                <div class="alert success"><i class="fas fa-check-circle"></i> <?php echo $success; ?></div>
                <p style="text-align:center;margin-top:16px;">
                    <a href="login.php" class="btn-primary" style="text-decoration:none;display:inline-flex;justify-content:center;padding:12px 24px;">
                        <i class="fas fa-sign-in-alt"></i> &nbsp;Go to Login
                    </a>
                </p>
            <?php else: ?>
            <form method="POST">
                <div class="form-group">
                    <label><i class="fas fa-lock"></i> New Password</label>
                    <input type="password" name="new_password" required placeholder="Min 6 characters" autofocus>
                </div>
                <div class="form-group">
                    <label><i class="fas fa-lock"></i> Confirm Password</label>
                    <input type="password" name="confirm_password" required placeholder="Re-enter new password">
                </div>
                <button type="submit" name="reset_pass" class="btn-primary" style="width:100%;justify-content:center;padding:12px;font-size:1rem;">
                    <i class="fas fa-save"></i> &nbsp;Reset Password
                </button>
            </form>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>