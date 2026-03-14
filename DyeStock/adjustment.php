<?php
require_once 'config/database.php';
requireLogin();

// Handle adjustment
$message = '';
if ($_POST && isset($_POST['create_adjustment'])) {
    $product_id = $_POST['product_id'];
    $quantity = (float)$_POST['quantity'];
    $reason = $_POST['reason'];
    
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare("SELECT current_stock FROM products WHERE id = ?");
        $stmt->execute([$product_id]);
        $current_stock = $stmt->fetchColumn();
        $new_stock = $current_stock + $quantity;
        
        if ($new_stock < 0) {
            throw new Exception("Stock cannot be negative!");
        }
        
        $stmt = $pdo->prepare("UPDATE products SET current_stock = ? WHERE id = ?");
        $stmt->execute([$new_stock, $product_id]);
        
        $movement_type = $quantity > 0 ? 'adjustment_in' : 'adjustment_out';
        $stmt = $pdo->prepare("
            INSERT INTO inventory_movements (product_id, movement_type, quantity, notes, balance_after, created_by) 
            VALUES (?, ?, ?, ?, ?, ?)
        ");
        $stmt->execute([$product_id, $movement_type, $quantity, $reason, $new_stock, getCurrentUserId()]);
        
        $pdo->commit();
        $message = "Adjustment recorded! New stock: " . $new_stock . "kg";
    } catch (Exception $e) {
        $pdo->rollBack();
        $message = "Error: " . $e->getMessage();
    }
}

$products = $pdo->query("SELECT * FROM products WHERE current_stock > 0 ORDER BY dye_name")->fetchAll();

$recent_adjustments = $pdo->query("
    SELECT im.*, p.dye_name, p.sku, u.username
    FROM inventory_movements im
    JOIN products p ON im.product_id = p.id
    LEFT JOIN users u ON im.created_by = u.id
    WHERE im.movement_type LIKE 'adjustment%'
    ORDER BY im.created_at DESC LIMIT 10
")->fetchAll();
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Adjustments - DyeStock</title>
    <link rel="stylesheet" href="assets/style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <?php include 'includes/sidebar.php'; ?>
    
    <main class="main-content">
        <header class="header">
            <div>
                <h1><i class="fas fa-balance-scale"></i> Stock Adjustments</h1>
                <p>Correct physical vs system stock differences</p>
            </div>
        </header>

        <?php if ($message): ?>
            <div class="alert <?php echo strpos($message, 'Error') === 0 ? 'error' : 'success'; ?>">
                <?php echo $message; ?>
            </div>
        <?php endif; ?>

        <div class="cards-grid">
            <div class="card full-width">
                <h3><i class="fas fa-wrench"></i> Record Adjustment</h3>
                <form method="POST">
                    <div class="form-row">
                        <div class="form-group">
                            <label>Product</label>
                            <select name="product_id" required>
                                <option value="">Select Product</option>
                                <?php foreach ($products as $product): ?>
                                    <option value="<?php echo $product['id']; ?>" data-current="<?php echo $product['current_stock']; ?>">
                                        <?php echo htmlspecialchars($product['dye_name']); ?> (<?php echo $product['sku']; ?>) 
                                        - Current: <?php echo $product['current_stock']; ?>kg
                                    </option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div class="form-group">
                            <label>Adjustment Amount</label>
                            <input type="number" name="quantity" step="0.01" required 
                                   placeholder="+10 for addition, -5 for deduction">
                        </div>
                    </div>
                    <div class="form-group">
                        <label>Reason *</label>
                        <select name="reason" required>
                            <option value="">Select reason</option>
                            <option value="Physical count difference">Physical count difference</option>
                            <option value="Damage/Spillage">Damage/Spillage</option>
                            <option value="Theft/Loss">Theft/Loss</option>
                            <option value="Sample taken">Sample taken</option>
                            <option value="Expired">Expired</option>
                            <option value="Other">Other</option>
                        </select>
                    </div>
                    <button type="submit" name="create_adjustment" class="btn-primary">
                        <i class="fas fa-save"></i> Record Adjustment
                    </button>
                </form>
            </div>
        </div>

        <div class="table-container">
            <h3>Recent Adjustments</h3>
            <table class="data-table">
                <thead>
                    <tr><th>Date</th><th>Product</th><th>Adjustment</th><th>Reason</th><th>New Balance</th><th>By</th></tr>
                </thead>
                <tbody>
                    <?php foreach ($recent_adjustments as $adj): ?>
                    <tr>
                        <td><?php echo date('M j H:i', strtotime($adj['created_at'])); ?></td>
                        <td><?php echo htmlspecialchars($adj['dye_name']); ?></td>
                        <td class="<?php echo $adj['quantity'] > 0 ? 'positive' : 'negative'; ?>">
                            <?php echo $adj['quantity'] > 0 ? '+' : ''; ?><?php echo $adj['quantity']; ?>kg
                        </td>
                        <td><?php echo htmlspecialchars($adj['notes']); ?></td>
                        <td><?php echo $adj['balance_after']; ?>kg</td>
                        <td><?php echo htmlspecialchars($adj['username'] ?? 'System'); ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </main>
    <script src="assets/script.js"></script>
</body>
</html>
