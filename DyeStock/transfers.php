<?php
require_once 'config/database.php';
requireLogin();

$message = '';
if ($_POST && isset($_POST['create_transfer'])) {
    $product_id        = (int)$_POST['product_id'];
    $quantity          = (float)$_POST['quantity'];
    $from_warehouse    = trim($_POST['from_warehouse']);
    $to_warehouse      = trim($_POST['to_warehouse']);
    $notes             = trim($_POST['notes'] ?? '');

    $pdo->beginTransaction();
    try {
        if ($from_warehouse === $to_warehouse) throw new Exception("Source and destination warehouses must be different!");

        $stmt = $pdo->prepare("SELECT current_stock FROM products WHERE id = ?");
        $stmt->execute([$product_id]);
        $current_stock = $stmt->fetchColumn();
        if ($current_stock < $quantity) throw new Exception("Insufficient stock! Available: {$current_stock}kg");

        $new_stock = $current_stock - $quantity;
        $pdo->prepare("UPDATE products SET current_stock = ? WHERE id = ?")->execute([$new_stock, $product_id]);

        $user_id      = getCurrentUserId();
        $transfer_note = "From: {$from_warehouse} → To: {$to_warehouse}" . ($notes ? " | {$notes}" : "");

        $pdo->prepare("INSERT INTO inventory_movements (product_id, movement_type, quantity, notes, balance_after, created_by) VALUES (?, 'transfer_out', ?, ?, ?, ?)")
            ->execute([$product_id, -$quantity, $transfer_note, $new_stock, $user_id]);

        $pdo->prepare("INSERT INTO inventory_movements (product_id, movement_type, quantity, notes, balance_after, created_by) VALUES (?, 'transfer_in', ?, ?, ?, ?)")
            ->execute([$product_id, $quantity, $transfer_note, $new_stock + $quantity, $user_id]);

        $pdo->commit();
        $message = "success:Transfer completed! {$quantity}kg moved from {$from_warehouse} to {$to_warehouse}.";
    } catch (Exception $e) {
        $pdo->rollBack();
        $message = "error:" . $e->getMessage();
    }
}

$products   = $pdo->query("SELECT * FROM products WHERE current_stock > 0 ORDER BY dye_name")->fetchAll();
$warehouses = $pdo->query("SELECT * FROM warehouses ORDER BY name")->fetchAll();
$transfers  = $pdo->query("
    SELECT im.*, p.dye_name, p.sku, u.username
    FROM inventory_movements im
    JOIN products p ON im.product_id = p.id
    LEFT JOIN users u ON im.created_by = u.id
    WHERE im.movement_type IN ('transfer_in','transfer_out')
    ORDER BY im.created_at DESC LIMIT 20
")->fetchAll();

$msg_type = $msg_text = '';
if ($message) { [$msg_type, $msg_text] = explode(':', $message, 2); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Transfers - DyeStock</title>
    <link rel="stylesheet" href="assets/style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <header class="header">
            <div>
                <h1><i class="fas fa-exchange-alt"></i> Transfers / Shelving</h1>
                <p>Move dyes between warehouses</p>
            </div>
        </header>

        <?php if ($msg_text): ?>
            <div class="alert <?php echo $msg_type; ?>">
                <?php echo $msg_type==='success' ? '✅' : '❌'; ?> <?php echo htmlspecialchars($msg_text); ?>
            </div>
        <?php endif; ?>

        <div class="cards-grid">
            <div class="card full-width">
                <h3><i class="fas fa-plus"></i> Create New Transfer</h3>
                <form method="POST">
                    <div class="form-row">
                        <div class="form-group">
                            <label>Product *</label>
                            <select name="product_id" required>
                                <option value="">Select Product</option>
                                <?php foreach ($products as $p): ?>
                                <option value="<?php echo $p['id']; ?>">
                                    <?php echo htmlspecialchars($p['dye_name']); ?> (<?php echo $p['sku']; ?>) — <?php echo $p['current_stock']; ?>kg
                                </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Quantity (kg) *</label>
                            <input type="number" name="quantity" step="0.01" min="0.01" required>
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label>From Warehouse *</label>
                            <select name="from_warehouse" required>
                                <option value="">Select Source</option>
                                <?php foreach ($warehouses as $wh): ?>
                                <option value="<?php echo htmlspecialchars($wh['name']); ?>">
                                    <?php echo htmlspecialchars($wh['name']); ?>
                                </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>To Warehouse *</label>
                            <select name="to_warehouse" required>
                                <option value="">Select Destination</option>
                                <?php foreach ($warehouses as $wh): ?>
                                <option value="<?php echo htmlspecialchars($wh['name']); ?>">
                                    <?php echo htmlspecialchars($wh['name']); ?>
                                </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Notes (Optional)</label>
                        <textarea name="notes" rows="2" placeholder="Reason for transfer, shelf location..."></textarea>
                    </div>
                    <button type="submit" name="create_transfer" class="btn-primary">
                        <i class="fas fa-exchange-alt"></i> Complete Transfer
                    </button>
                </form>
            </div>
        </div>

        <div class="table-container">
            <div class="table-header">
                <h3>Recent Transfers</h3>
                <span style="color:#94a3b8;font-size:0.85rem;"><?php echo count($transfers); ?> records</span>
            </div>
            <table class="data-table">
                <thead>
                    <tr><th>Date</th><th>Product</th><th>Type</th><th>Qty</th><th>Location Details</th><th>Balance</th><th>By</th></tr>
                </thead>
                <tbody>
                    <?php foreach ($transfers as $t): ?>
                    <tr>
                        <td><?php echo date('M j, Y H:i', strtotime($t['created_at'])); ?></td>
                        <td>
                            <strong><?php echo htmlspecialchars($t['dye_name']); ?></strong><br>
                            <small style="color:#94a3b8;"><?php echo $t['sku']; ?></small>
                        </td>
                        <td>
                            <span class="movement-type <?php echo $t['movement_type']; ?>">
                                <?php echo ucwords(str_replace('_', ' ', $t['movement_type'])); ?>
                            </span>
                        </td>
                        <td class="<?php echo $t['quantity'] < 0 ? 'negative' : 'positive'; ?>">
                            <?php echo $t['quantity'] > 0 ? '+' : ''; ?><?php echo abs($t['quantity']); ?> kg
                        </td>
                        <td style="font-size:0.85rem;color:#64748b;"><?php echo htmlspecialchars($t['notes'] ?? '—'); ?></td>
                        <td><strong><?php echo $t['balance_after']; ?> kg</strong></td>
                        <td><?php echo htmlspecialchars($t['username'] ?? 'System'); ?></td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (!$transfers): ?>
                    <tr><td colspan="7" style="text-align:center;color:#94a3b8;padding:2rem;">No transfers yet.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </main>
    <script src="assets/script.js"></script>
</body>
</html>