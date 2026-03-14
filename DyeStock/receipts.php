<?php
require_once 'config/database.php';
requireLogin();

$message = '';
if ($_POST && isset($_POST['create_receipt'])) {
    $product_id   = (int)$_POST['product_id'];
    $quantity     = (float)$_POST['quantity'];
    $supplier     = trim($_POST['supplier_name']);
    $reference_no = trim($_POST['reference_no']);
    $notes        = trim($_POST['notes']);

    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare("SELECT current_stock FROM products WHERE id = ?");
        $stmt->execute([$product_id]);
        $current_stock = $stmt->fetchColumn();
        $new_stock = $current_stock + $quantity;

        $pdo->prepare("UPDATE products SET current_stock = ? WHERE id = ?")->execute([$new_stock, $product_id]);
        $pdo->prepare("INSERT INTO inventory_movements (product_id, movement_type, quantity, company_name, reference_no, notes, balance_after, created_by) VALUES (?, 'receipt', ?, ?, ?, ?, ?, ?)")
            ->execute([$product_id, $quantity, $supplier, $reference_no, $notes, $new_stock, getCurrentUserId()]);

        $pdo->commit();
        $message = "success:Receipt recorded! New stock: {$new_stock}kg";
    } catch (Exception $e) {
        $pdo->rollBack();
        $message = "error:" . $e->getMessage();
    }
}

$products = $pdo->query("SELECT * FROM products ORDER BY dye_name")->fetchAll();
$receipts = $pdo->query("
    SELECT im.*, p.dye_name, p.sku, u.username
    FROM inventory_movements im
    JOIN products p ON im.product_id = p.id
    LEFT JOIN users u ON im.created_by = u.id
    WHERE im.movement_type = 'receipt'
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
    <title>Receipts - DyeStock</title>
    <link rel="stylesheet" href="assets/style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <header class="header">
            <div>
                <h1><i class="fas fa-download"></i> Receipts (Incoming Stock)</h1>
                <p>Record new dye stock arrivals</p>
            </div>
        </header>

        <?php if ($msg_text): ?>
            <div class="alert <?php echo $msg_type; ?>">
                <?php echo $msg_type==='success' ? '✅' : '❌'; ?> <?php echo htmlspecialchars($msg_text); ?>
            </div>
        <?php endif; ?>

        <div class="cards-grid">
            <div class="card full-width">
                <h3><i class="fas fa-plus"></i> Record Incoming Stock</h3>
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
                            <input type="number" name="quantity" step="0.01" min="0.01" required placeholder="e.g. 50.00">
                        </div>
                    </div>
                    <div class="form-row">
                        <div class="form-group">
                            <label><i class="fas fa-building"></i> Supplier Name</label>
                            <input type="text" name="supplier_name" placeholder="e.g. ColorChem Ltd">
                        </div>
                        <div class="form-group">
                            <label><i class="fas fa-file-invoice"></i> Reference / Invoice No</label>
                            <input type="text" name="reference_no" placeholder="e.g. INV-2024-001">
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Notes</label>
                        <textarea name="notes" rows="2" placeholder="Optional notes..."></textarea>
                    </div>
                    <button type="submit" name="create_receipt" class="btn-primary">
                        <i class="fas fa-save"></i> Record Receipt
                    </button>
                </form>
            </div>
        </div>

        <div class="table-container">
            <div class="table-header">
                <h3>Recent Receipts</h3>
                <span style="color:#94a3b8;font-size:0.85rem;"><?php echo count($receipts); ?> records</span>
            </div>
            <table class="data-table">
                <thead>
                    <tr><th>Date</th><th>Product</th><th>Qty Added</th><th>Supplier</th><th>Reference</th><th>New Balance</th><th>By</th></tr>
                </thead>
                <tbody>
                    <?php foreach ($receipts as $r): ?>
                    <tr>
                        <td><?php echo date('M j, Y H:i', strtotime($r['created_at'])); ?></td>
                        <td>
                            <strong><?php echo htmlspecialchars($r['dye_name']); ?></strong><br>
                            <small style="color:#94a3b8;"><?php echo $r['sku']; ?></small>
                        </td>
                        <td class="positive">+<?php echo $r['quantity']; ?> kg</td>
                        <td><?php echo htmlspecialchars($r['company_name'] ?? '—'); ?></td>
                        <td><?php echo htmlspecialchars($r['reference_no'] ?? '—'); ?></td>
                        <td><strong><?php echo $r['balance_after']; ?> kg</strong></td>
                        <td><?php echo htmlspecialchars($r['username'] ?? 'System'); ?></td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (!$receipts): ?>
                    <tr><td colspan="7" style="text-align:center;color:#94a3b8;padding:2rem;">No receipts yet.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </main>
    <script src="assets/script.js"></script>
</body>
</html>