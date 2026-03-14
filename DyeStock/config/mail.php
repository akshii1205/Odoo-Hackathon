<?php
define('SMTP_FROM',      'your@gmail.com');
define('SMTP_FROM_NAME', 'DyeStock');

function sendOTPEmail($to_email, $to_name, $otp_code, $purpose = 'first_login') {
    if ($purpose === 'first_login') {
        $subject  = "Activate Your DyeStock Account — OTP: {$otp_code}";
        $headline = "Account Activation";
        $msg      = "Your staff account has been created. Use this OTP to verify and activate your account.";
        $color    = "#1e3ab8";
    } else {
        $subject  = "DyeStock Password Reset OTP — {$otp_code}";
        $headline = "Password Reset";
        $msg      = "Use the OTP below to reset your DyeStock password.";
        $color    = "#dc2626";
    }

    $body = "<!DOCTYPE html><html><body style='font-family:Segoe UI,sans-serif;background:#f0f2f8;padding:30px;'>
    <div style='max-width:480px;margin:0 auto;background:#fff;border-radius:16px;overflow:hidden;'>
        <div style='background:{$color};padding:24px;text-align:center;'>
            <h1 style='color:#fff;margin:0;'>🧵 DyeStock</h1>
        </div>
        <div style='padding:32px;text-align:center;'>
            <h2 style='color:#0f172a;'>{$headline}</h2>
            <p style='color:#64748b;'>Hello <strong>{$to_name}</strong>, {$msg}</p>
            <div style='background:#f0f2f8;border-radius:12px;padding:24px;margin:20px 0;'>
                <div style='font-size:2.8rem;font-weight:800;letter-spacing:12px;color:{$color};'>{$otp_code}</div>
                <p style='color:#94a3b8;font-size:0.85rem;margin-top:8px;'>Valid for 10 minutes</p>
            </div>
        </div>
    </div></body></html>";

    $headers  = "MIME-Version: 1.0\r\n";
    $headers .= "Content-Type: text/html; charset=UTF-8\r\n";
    $headers .= "From: " . SMTP_FROM_NAME . " <" . SMTP_FROM . ">\r\n";

    // @ suppresses the mail() warning on screen
    return @mail($to_email, $subject, $body, $headers);
}
?>