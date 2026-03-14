<?php
require_once 'config/database.php';
require_once 'config/mail.php';
if (isLoggedIn()) { header('Location: dashboard.php'); exit; }

$error = $success = '';

if ($_POST && isset($_POST['send_otp'])) {
    $email = trim($_POST['email']);
    $stmt  = $pdo->prepare("SELECT * FROM users WHERE email = ? LIMIT 1");
    $stmt->execute([$email]);
    $user = $stmt->fetch();

    if ($user) {
        $otp     = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
        $expires = date('Y-m-d H:i:s', time() + 600);

        $pdo->prepare("DELETE FROM otp_codes WHERE user_id = ? AND used = 0 AND purpose = 'forgot_password'")->execute([$user['id']]);
        $pdo->prepare("INSERT INTO otp_codes (user_id, otp_code, expires_at, purpose) VALUES (?, ?, ?, 'forgot_password')")
            ->execute([$user['id'], $otp, $expires]);

        $sent = sendOTPEmail($user['email'], $user['username'], $otp, 'forgot_password');

        $_SESSION['otp_user_id'] = $user['id'];
        $_SESSION['otp_step']    = 'otp';
        $_SESSION['otp_email']   = $user['email'];
        $_SESSION['otp_purpose'] = 'forgot_password';

        header('Location: login.php?step=otp&reason=forgot_password' . (!$sent ? '&dev_otp='.$otp : '')); exit;
    } else {
        // Don't reveal if email exists — show same message
        $success = 'If that email exists, an OTP has been sent.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forgot Password - DyeStock</title>
    <link rel="stylesheet" href="assets/style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body class="login-page">
    <div class="login-container">
        <div class="login-card">
            <div class="logo">
                <h1><i class="fas fa-key"></i> Forgot Password</h1>
                <p>Enter your email to receive an OTP</p>
            </div>

            <?php if ($error):   ?><div class="alert error">  <i class="fas fa-exclamation-circle"></i> <?php echo $error;   ?></div><?php endif; ?>
            <?php if ($success): ?><div class="alert success"><i class="fas fa-check-circle"></i> <?php echo $success; ?></div><?php endif; ?>

            <form method="POST">
                <div class="form-group">
                    <label><i class="fas fa-envelope"></i> Email Address</label>
                    <input type="email" name="email" required autofocus placeholder="Enter your registered email">
                </div>
                <button type="submit" name="send_otp" class="btn-primary" style="width:100%;justify-content:center;padding:12px;font-size:1rem;">
                    <i class="fas fa-paper-plane"></i> &nbsp;Send OTP
                </button>
            </form>
            <p style="text-align:center;margin-top:16px;font-size:0.85rem;">
                <a href="login.php" style="color:#3b82f6;"><i class="fas fa-arrow-left"></i> Back to Login</a>
            </p>
        </div>
    </div>
</body>
</html>