<?php
require_once 'config/database.php';
requireManager();

$filter_type    = $_GET['type']    ?? '';
$filter_product = $_GET['product'] ?? '';
$filter_date    = $_GET['date']    ?? '';

$where  = "WHERE 1=1";
$params = [];
if ($filter_type)    { $where .= " AND im.movement_type = ?"; $params[] = $filter_type; }
if ($filter_product) { $where .= " AND p.id = ?";             $params[] = $filter_product; }
if ($filter_date)    { $where .= " AND DATE(im.created_at) = ?"; $params[] = $filter_date; }

$stmt = $pdo->prepare("
    SELECT im.*, p.dye_name, p.sku, p.unit, u.username
    FROM inventory_movements im
    JOIN products p ON im.product_id = p.id
    LEFT JOIN users u ON im.created_by = u.id
    $where
    ORDER BY im.created_at DESC
    LIMIT 100
");
$stmt->execute($params);
$movements = $stmt->fetchAll();

$products = $pdo->query("SELECT id, dye_name, sku FROM products ORDER BY dye_name")->fetchAll();
$types    = ['receipt','delivery','transfer_in','transfer_out','adjustment_in','adjustment_out'];
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>History - DyeStock</title>
    <link rel="stylesheet" href="assets/style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
</head>
<body>
    <?php include 'includes/sidebar.php'; ?>
    <main class="main-content">
        <header class="header">
            <div>
                <h1><i class="fas fa-history"></i> Transaction History</h1>
                <p>Full inventory movement ledger</p>
            </div>
        </header>

        <div class="card" style="margin-bottom:18px;">
            <form method="GET" style="display:flex;flex-wrap:wrap;gap:14px;align-items:flex-end;">
                <div class="form-group" style="margin-bottom:0;min-width:160px;flex:1;">
                    <label>Movement Type</label>
                    <select name="type">
                        <option value="">All Types</option>
                        <?php foreach ($types as $type): ?>
                        <option value="<?php echo $type; ?>" <?php echo $filter_type==$type?'selected':''; ?>>
                            <?php echo ucwords(str_replace('_',' ',$type)); ?>
                        </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group" style="margin-bottom:0;min-width:160px;flex:1;">
                    <label>Product</label>
                    <select name="product">
                        <option value="">All Products</option>
                        <?php foreach ($products as $p): ?>
                        <option value="<?php echo $p['id']; ?>" <?php echo $filter_product==$p['id']?'selected':''; ?>>
                            <?php echo htmlspecialchars($p['dye_name']); ?> (<?php echo $p['sku']; ?>)
                        </option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-group" style="margin-bottom:0;min-width:140px;">
                    <label>Date</label>
                    <input type="date" name="date" value="<?php echo $filter_date; ?>">
                </div>
                <div style="display:flex;gap:10px;">
                    <button type="submit" class="btn-primary"><i class="fas fa-search"></i> Filter</button>
                    <a href="history.php" class="btn-secondary">✕ Clear</a>
                </div>
            </form>
        </div>

        <div class="table-container">
            <div class="table-header">
                <h3>Transaction Ledger</h3>
                <span style="color:#94a3b8;font-size:0.85rem;"><?php echo count($movements); ?> records</span>
            </div>
            <table class="data-table">
                <thead>
                    <tr>
                        <th>Date & Time</th><th>Product</th><th>Type</th>
                        <th>Quantity</th><th>Balance</th><th>Company / Notes</th><th>By</th>
                    </tr>
                </thead>
                <tbody>
                    <?php foreach ($movements as $m): ?>
                    <tr>
                        <td><?php echo date('M j, Y H:i', strtotime($m['created_at'])); ?></td>
                        <td>
                            <strong><?php echo htmlspecialchars($m['dye_name']); ?></strong><br>
                            <small style="color:#94a3b8;"><?php echo $m['sku']; ?></small>
                        </td>
                        <td>
                            <span class="movement-type <?php echo $m['movement_type']; ?>">
                                <?php echo ucwords(str_replace('_',' ',$m['movement_type'])); ?>
                            </span>
                        </td>
                        <td class="<?php echo $m['quantity'] < 0 ? 'negative':'positive'; ?>">
                            <?php echo $m['quantity'] > 0 ? '+':''; ?><?php echo abs($m['quantity']); ?> <?php echo $m['unit']; ?>
                        </td>
                        <td><strong><?php echo $m['balance_after']; ?> <?php echo $m['unit']; ?></strong></td>
                        <td style="font-size:0.85rem;color:#64748b;">
                            <?php if (!empty($m['company_name'])): ?>
                                <i class="fas fa-building" style="color:#3b82f6;margin-right:4px;"></i>
                                <?php echo htmlspecialchars($m['company_name']); ?><br>
                            <?php endif; ?>
                            <?php if (!empty($m['reference_no'])): ?>
                                <small><?php echo htmlspecialchars($m['reference_no']); ?></small><br>
                            <?php endif; ?>
                            <?php if (!empty($m['notes'])): ?>
                                <small style="color:#94a3b8;"><?php echo htmlspecialchars($m['notes']); ?></small>
                            <?php endif; ?>
                            <?php if (empty($m['company_name']) && empty($m['reference_no']) && empty($m['notes'])): ?>—<?php endif; ?>
                        </td>
                        <td><?php echo htmlspecialchars($m['username'] ?? 'System'); ?></td>
                    </tr>
                    <?php endforeach; ?>
                    <?php if (!$movements): ?>
                    <tr><td colspan="7" style="text-align:center;color:#94a3b8;padding:2rem;">No transactions found.</td></tr>
                    <?php endif; ?>
                </tbody>
            </table>
        </div>
    </main>
    <script src="assets/script.js"></script>
</body>
</html>