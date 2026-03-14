<?php
require_once 'config/database.php';
requireLogin();

$message = '';
if ($_POST && isset($_POST['create_delivery'])) {
    $product_id   = (int)$_POST['product_id'];
    $quantity     = (float)$_POST['quantity'];
    $company_name = trim($_POST['company_name']);
    $reference_no = trim($_POST['reference_no']);
    $notes        = trim($_POST['notes']);

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare("SELECT current_stock FROM products WHERE id = ?");
        $stmt->execute([$product_id]);
        $current_stock = $stmt->fetchColumn();

        if ($current_stock < $quantity) throw new Exception("Insufficient stock! Available: {$current_stock}kg");

        $new_stock = $current_stock - $quantity;
        $pdo->prepare("UPDATE products SET current_stock = ? WHERE id = ?")->execute([$new_stock, $product_id]);
        $pdo->prepare("INSERT INTO inventory_movements (product_id, movement_type, quantity, company_name, reference_no, notes, balance_after, created_by) VALUES (?, 'delivery', ?, ?, ?, ?, ?, ?)")
            ->execute([$product_id, -$quantity, $company_name, $reference_no, $notes, $new_stock, getCurrentUserId()]);

        $pdo->commit();
        $message = "success:Delivery recorded! Remaining stock: {$new_stock}kg";
    } catch (Exception $e) {
        $pdo->rollBack();
        $message = "error:" . $e->getMessage();
    }
}

$products   = $pdo->query("SELECT * FROM products WHERE current_stock > 0 ORDER BY dye_name")->fetchAll();
$deliveries = $pdo->query("
    SELECT im.*, p.dye_name, p.sku, u.username
    FROM inventory_movements im
    JOIN products p ON im.product_id = p.id
    LEFT JOIN users u ON im.created_by = u.id
    WHERE im.movement_type = 'delivery'
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
    <title>Deliveries - DyeStock</title>
    <link rel="stylesheet" href="assets/style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <header class="header">
            <div>
                <h1><i class="fas fa-upload"></i> Deliveries (Outgoing Stock)</h1>
                <p>Record dye dispatch to companies</p>
            </div>
        </header>

        <?php if ($msg_text): ?>
            <div class="alert <?php echo $msg_type; ?>">
                <?php echo $msg_type === 'success' ? '✅' : '❌'; ?> <?php echo htmlspecialchars($msg_text); ?>
            </div>
        <?php endif; ?>

        <div class="cards-grid">
            <div class="card full-width">
                <h3><i class="fas fa-truck"></i> Record Outgoing Delivery</h3>
                <form method="POST">
                    <div class="form-row">
                        <div class="form-group">
                            <label>Product *</label>
                            <select name="product_id" required>
                                <option value="">Select Product</option>
                                <?php foreach ($products as $p): ?>
                                <option value="<?php echo $p['id']; ?>">
                                    <?php echo htmlspecialchars($p['dye_name']); ?> (<?php echo $p['sku']; ?>) — <?php echo $p['current_stock']; ?>kg available
                                </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Quantity (kg) *</label>
                            <input type="number" name="quantity" step="0.01" min="0.01" required placeholder="Amount to deliver">
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label><i class="fas fa-building"></i> Company Name *</label>
                            <input type="text" name="company_name" required placeholder="e.g. Sharma Textiles Pvt Ltd">
                        </div>
                        <div class="form-group">
                            <label><i class="fas fa-file-invoice"></i> Delivery / Invoice No</label>
                            <input type="text" name="reference_no" placeholder="e.g. DEL-2024-001">
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Notes (Optional)</label>
                        <textarea name="notes" rows="2" placeholder="e.g. Production order details, special instructions..."></textarea>
                    </div>
                    <button type="submit" name="create_delivery" class="btn-primary">
                        <i class="fas fa-save"></i> Record Delivery
                    </button>
                </form>
            </div>
        </div>

        <div class="table-container">
            <div class="table-header">
                <h3>Recent Deliveries</h3>
                <span style="color:#94a3b8;font-size:0.85rem;"><?php echo count($deliveries); ?> records</span>
            </div>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Product</th>
                        <th>Company Name</th>
                        <th>Invoice No</th>
                        <th>Qty Delivered</th>
                        <th>Remaining Stock</th>
                        <th>Notes</th>
                        <th>By</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($deliveries as $d): ?>
                    <tr>
                        <td><?php echo date('M j, Y H:i', strtotime($d['created_at'])); ?></td>
                        <td>
                            <strong><?php echo htmlspecialchars($d['dye_name']); ?></strong><br>
                            <small style="color:#94a3b8;"><?php echo $d['sku']; ?></small>
                        </td>
                        <td>
                            <?php if (!empty($d['company_name'])): ?>
                                <span style="display:inline-flex;align-items:center;gap:5px;">
                                    <i class="fas fa-building" style="color:#3b82f6;font-size:0.8rem;"></i>
                                    <strong><?php echo htmlspecialchars($d['company_name']); ?></strong>
                                </span>
                            <?php else: ?>
                                <span style="color:#94a3b8;">—</span>
                            <?php endif; ?>
                        </td>
                        <td><?php echo htmlspecialchars($d['reference_no'] ?? '—'); ?></td>
                        <td class="negative">
                            <strong><?php echo abs($d['quantity']); ?> kg</strong>
                        </td>
                        <td><strong><?php echo $d['balance_after']; ?> kg</strong></td>
                        <td style="color:#64748b;font-size:0.85rem;"><?php echo htmlspecialchars($d['notes'] ?? '—'); ?></td>
                        <td><?php echo htmlspecialchars($d['username'] ?? 'System'); ?></td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (!$deliveries): ?>
                    <tr>
                        <td colspan="8" style="text-align:center;color:#94a3b8;padding:2rem;">
                            No deliveries yet.
                        </td>
                    </tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </main>
    <script src="assets/script.js"></script>
</body>
</html>