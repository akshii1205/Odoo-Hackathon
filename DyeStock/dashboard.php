<?php
require_once 'config/database.php';
requireLogin();

$total_products  = $pdo->query("SELECT COUNT(*) FROM products")->fetchColumn();
$low_stock       = $pdo->query("SELECT COUNT(*) FROM products WHERE current_stock <= min_stock_level")->fetchColumn();
$today_movements = $pdo->query("SELECT COUNT(*) FROM inventory_movements WHERE DATE(created_at) = CURDATE()")->fetchColumn();
$warehouses      = $pdo->query("SELECT COUNT(*) FROM warehouses")->fetchColumn();

// Staff: only their own today's movements
$my_today = $pdo->prepare("SELECT COUNT(*) FROM inventory_movements WHERE DATE(created_at) = CURDATE() AND created_by = ?");
$my_today->execute([getCurrentUserId()]);
$my_today_count = $my_today->fetchColumn();

$recent_movements = $pdo->query("
    SELECT im.*, p.dye_name, p.sku, u.username
    FROM inventory_movements im
    JOIN products p ON im.product_id = p.id
    LEFT JOIN users u ON im.created_by = u.id
    ORDER BY im.created_at DESC LIMIT 5
")->fetchAll();

$access_error = $_GET['error'] ?? '';
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard - DyeStock</title>
    <link rel="stylesheet" href="assets/style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .stats-grid { display:grid; grid-template-columns:repeat(4,1fr); gap:18px; margin-bottom:22px; }
        a.stat-card {
            background:#fff; border-radius:16px; padding:28px 16px 22px;
            text-align:center; box-shadow:0 2px 12px rgba(0,0,0,0.07);
            border-top:3.5px solid #3b82f6; text-decoration:none; display:block;
            transition:transform 0.2s, box-shadow 0.2s; cursor:pointer;
        }
        a.stat-card:hover { transform:translateY(-4px); box-shadow:0 10px 28px rgba(30,58,175,0.13); }
        a.stat-card.warn  { border-top-color:#f59e0b; }
        a.stat-card.green { border-top-color:#10b981; }
        a.stat-card.warn:hover { box-shadow:0 10px 28px rgba(245,158,11,0.15); }
        .sicon { font-size:2.8rem; display:block; margin-bottom:14px; line-height:1; }
        .sval  { font-size:2.6rem; font-weight:800; color:#1e3ab8; line-height:1; margin-bottom:8px; letter-spacing:-1px; }
        .slbl  { color:#64748b; font-size:0.88rem; font-weight:500; }
        .db-panel { background:#fff; border-radius:16px; box-shadow:0 2px 12px rgba(0,0,0,0.07); padding:24px 26px; margin-bottom:22px; }
        .db-panel-title { font-size:1.05rem; font-weight:700; color:#0f172a; margin-bottom:20px; display:flex; align-items:center; gap:8px; }
        .qa-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:16px; }
        a.qa-card {
            border-radius:14px; padding:22px 16px; text-align:center;
            text-decoration:none; display:block; background:#fff;
            border:2px solid #3b82f6; transition:transform 0.2s,box-shadow 0.2s;
        }
        a.qa-card:hover { transform:translateY(-3px); box-shadow:0 6px 20px rgba(0,0,0,0.10); }
        a.qa-card.green  { border-color:#10b981; }
        a.qa-card.red    { border-color:#ef4444; }
        a.qa-card.purple { border-color:#8b5cf6; }
        a.qa-card.amber  { border-color:#f59e0b; }
        a.qa-card.slate  { border-color:#64748b; }
        .qicon { font-size:2.2rem; display:block; margin-bottom:10px; line-height:1; }
        .qlbl  { font-weight:700; font-size:0.93rem; color:#1e3ab8; }
        a.qa-card.green  .qlbl { color:#065f46; }
        a.qa-card.red    .qlbl { color:#991b1b; }
        a.qa-card.purple .qlbl { color:#5b21b6; }
        a.qa-card.amber  .qlbl { color:#92400e; }
        a.qa-card.slate  .qlbl { color:#475569; }
        .panel-row { display:flex; justify-content:space-between; align-items:center; margin-bottom:16px; }
        .panel-row .db-panel-title { margin-bottom:0; }
        .view-all { font-size:0.85rem; font-weight:600; color:#3b82f6; text-decoration:none; }
        .view-all:hover { text-decoration:underline; }
        table.rt { width:100%; border-collapse:collapse; }
        table.rt th { text-align:left; font-size:0.76rem; font-weight:700; color:#94a3b8; text-transform:uppercase; letter-spacing:0.05em; padding:8px 14px; border-bottom:1.5px solid #f1f5f9; }
        table.rt td { padding:12px 14px; border-bottom:1px solid #f8fafc; font-size:0.88rem; color:#334155; }
        table.rt tr:last-child td { border-bottom:none; }
        table.rt tbody tr:hover { background:#f8fafc; }
        .tdname { font-weight:600; color:#0f172a; }
        .tdsku  { font-size:0.78rem; color:#94a3b8; margin-top:2px; }
        .pos { color:#16a34a; font-weight:600; }
        .neg { color:#dc2626; font-weight:600; }
        .mt { display:inline-block; padding:3px 10px; border-radius:20px; font-size:0.76rem; font-weight:600; }
        .mt.receipt        { background:#dcfce7; color:#166534; }
        .mt.delivery       { background:#fee2e2; color:#991b1b; }
        .mt.transfer_in    { background:#dbeafe; color:#1e40af; }
        .mt.transfer_out   { background:#fef3c7; color:#92400e; }
        .mt.adjustment_in  { background:#f3e8ff; color:#6b21a8; }
        .mt.adjustment_out { background:#fde68a; color:#78350f; }
        .empty { text-align:center; color:#94a3b8; padding:2rem; font-size:0.93rem; }

        /* Staff welcome banner */
        .staff-banner {
            background:linear-gradient(135deg,#1e3ab8,#3b82f6);
            color:white; border-radius:16px; padding:20px 26px;
            margin-bottom:22px; display:flex; align-items:center; gap:16px;
        }
        .staff-banner i { font-size:2rem; opacity:0.9; }
        .staff-banner h3 { font-size:1.1rem; font-weight:700; margin-bottom:3px; }
        .staff-banner p  { font-size:0.88rem; opacity:0.85; }

        /* Access denied alert */
        .alert-denied {
            background:#fef2f2; color:#dc2626; border:1px solid #fecaca;
            border-radius:10px; padding:12px 16px; margin-bottom:18px;
            display:flex; align-items:center; gap:10px; font-size:0.9rem; font-weight:500;
        }
    </style>
</head>
<body>
<?php include 'includes/sidebar.php'; ?>
<main class="main-content">

    <header class="header">
        <div>
            <h1>
                <?php if (isManager()): ?>
                    <i class="fas fa-chart-bar"></i> Dashboard
                <?php else: ?>
                    <i class="fas fa-hard-hat"></i> Staff Dashboard
                <?php endif; ?>
            </h1>
            <p>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?> &nbsp;·&nbsp;
                <?php if (isManager()): ?>
                    <span style="color:#f59e0b;font-weight:600;"><i class="fas fa-user-tie"></i> Inventory Manager</span>
                <?php else: ?>
                    <span style="color:#10b981;font-weight:600;"><i class="fas fa-hard-hat"></i> Warehouse Staff</span>
                <?php endif; ?>
            </p>
        </div>
    </header>

    <?php if ($access_error === 'access_denied'): ?>
    <div class="alert-denied">
        <i class="fas fa-lock"></i>
        You don't have permission to access that page. Please contact your manager.
    </div>
    <?php endif; ?>

    <?php if (isManager()): ?>
    <!-- ══════════════ MANAGER DASHBOARD ══════════════ -->

    <div class="stats-grid">
        <a href="products.php" class="stat-card">
            <span class="sicon">📦</span>
            <div class="sval"><?php echo $total_products; ?></div>
            <div class="slbl">Total Dyes in Stock</div>
        </a>
        <a href="products.php" class="stat-card warn">
            <span class="sicon">⚠️</span>
            <div class="sval"><?php echo $low_stock; ?></div>
            <div class="slbl">Low Stock Alerts</div>
        </a>
        <a href="history.php?date=<?php echo date('Y-m-d'); ?>" class="stat-card">
            <span class="sicon">📈</span>
            <div class="sval"><?php echo $today_movements; ?></div>
            <div class="slbl">Today's Movements</div>
        </a>
        <a href="transfers.php" class="stat-card">
            <span class="sicon">🏭</span>
            <div class="sval"><?php echo $warehouses; ?></div>
            <div class="slbl">Warehouses</div>
        </a>
    </div>

    <div class="db-panel">
        <div class="db-panel-title">🚀 Quick Actions</div>
        <div class="qa-grid">
            <a href="products.php"   class="qa-card">       <span class="qicon">📦</span><div class="qlbl">Manage Products</div></a>
            <a href="receipts.php"   class="qa-card green">  <span class="qicon">📥</span><div class="qlbl">Receive Stock</div></a>
            <a href="deliveries.php" class="qa-card red">    <span class="qicon">📤</span><div class="qlbl">Record Delivery</div></a>
            <a href="transfers.php"  class="qa-card purple"> <span class="qicon">🔄</span><div class="qlbl">Transfer Stock</div></a>
            <a href="adjustment.php" class="qa-card amber">  <span class="qicon">⚖️</span><div class="qlbl">Stock Adjustment</div></a>
            <a href="history.php"    class="qa-card slate">  <span class="qicon">📋</span><div class="qlbl">View History</div></a>
        </div>
    </div>

    <?php else: ?>
    <!-- ══════════════ STAFF DASHBOARD ══════════════ -->


    <div class="stats-grid" style="grid-template-columns:repeat(3,1fr);">
        <a href="receipts.php" class="stat-card green">
            <span class="sicon">📥</span>
            <div class="sval"><?php echo $total_products; ?></div>
            <div class="slbl">Products Available</div>
        </a>
        <a href="transfers.php" class="stat-card">
            <span class="sicon">🏭</span>
            <div class="sval"><?php echo $warehouses; ?></div>
            <div class="slbl">Warehouses</div>
        </a>
        <a href="deliveries.php" class="stat-card">
            <span class="sicon">📈</span>
            <div class="sval"><?php echo $my_today_count; ?></div>
            <div class="slbl">My Tasks Today</div>
        </a>
    </div>

    <div class="db-panel">
        <div class="db-panel-title">🏗️ Warehouse Tasks</div>
        <div class="qa-grid">
            <a href="receipts.php"   class="qa-card green">
                <span class="qicon">📥</span>
                <div class="qlbl">Receive Stock</div>
                <div style="font-size:0.78rem;color:#6b7280;margin-top:6px;">Shelving incoming dyes</div>
            </a>
            <a href="deliveries.php" class="qa-card red">
                <span class="qicon">📤</span>
                <div class="qlbl">Dispatch / Picking</div>
                <div style="font-size:0.78rem;color:#6b7280;margin-top:6px;">Pick & pack outgoing orders</div>
            </a>
            <a href="transfers.php"  class="qa-card purple">
                <span class="qicon">🔄</span>
                <div class="qlbl">Transfers / Counting</div>
                <div style="font-size:0.78rem;color:#6b7280;margin-top:6px;">Move stock between locations</div>
            </a>
        </div>
    </div>

    <?php endif; ?>

    <!-- RECENT ACTIVITY — both roles see this -->
    <div class="db-panel">
        <div class="panel-row">
            <div class="db-panel-title">🕐 Recent Activity</div>
            <?php if (isManager()): ?>
            <a href="history.php" class="view-all">View All →</a>
            <?php endif; ?>
        </div>
        <?php if ($recent_movements): ?>
        <table class="rt">
            <thead>
                <tr>
                    <th>Date & Time</th>
                    <th>Product</th>
                    <th>Type</th>
                    <th>Quantity</th>
                    <th>Balance After</th>
                    <th>By</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($recent_movements as $m): ?>
                <tr>
                    <td><?php echo date('M j, Y H:i', strtotime($m['created_at'])); ?></td>
                    <td>
                        <div class="tdname"><?php echo htmlspecialchars($m['dye_name']); ?></div>
                        <div class="tdsku"><?php echo $m['sku']; ?></div>
                    </td>
                    <td><span class="mt <?php echo $m['movement_type']; ?>"><?php echo ucwords(str_replace('_',' ',$m['movement_type'])); ?></span></td>
                    <td class="<?php echo $m['quantity'] < 0 ? 'neg':'pos'; ?>">
                        <?php echo $m['quantity'] > 0 ? '+':''; ?><?php echo abs($m['quantity']); ?> kg
                    </td>
                    <td><strong><?php echo $m['balance_after']; ?> kg</strong></td>
                    <td><?php echo htmlspecialchars($m['username'] ?? 'System'); ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <?php else: ?>
        <div class="empty">No transactions yet.</div>
        <?php endif; ?>
    </div>

</main>
<script src="assets/script.js"></script>
</body>
</html>