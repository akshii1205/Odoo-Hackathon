<?php
require_once 'config/database.php';
requireManager();

$message = '';
if ($_POST && isset($_POST['add_product'])) {
    $dye_name  = trim($_POST['dye_name']);
    $sku       = trim($_POST['sku']);
    $unit      = $_POST['unit'] ?? 'kg';
    $min_stock = (float)($_POST['min_stock_level'] ?? 0);
    $warehouse = (int)$_POST['warehouse_id'];
    $cat_id    = (int)$_POST['category_id'];
    try {
        $stmt = $pdo->prepare("INSERT INTO products (dye_name, sku, category_id, unit, min_stock_level, warehouse_id, current_stock) VALUES (?,?,?,?,?,?,0)");
        $stmt->execute([$dye_name, $sku, $cat_id, $unit, $min_stock, $warehouse]);
        $message = 'success:Product added successfully!';
    } catch (Exception $e) {
        $message = 'error:' . $e->getMessage();
    }
}

// Search & Filter
$search    = trim($_GET['search']    ?? '');
$wh_filter = $_GET['warehouse'] ?? '';

$where  = "WHERE 1=1";
$params = [];

if ($search) {
    $where .= " AND (p.dye_name LIKE ? OR p.sku LIKE ?)";
    $params[] = "%$search%";
    $params[] = "%$search%";
}
if ($wh_filter) {
    $where .= " AND p.warehouse_id = ?";
    $params[] = $wh_filter;
}

$stmt = $pdo->prepare("
    SELECT p.*, c.name AS category_name, w.name AS warehouse_name
    FROM products p
    LEFT JOIN categories c ON p.category_id = c.id
    LEFT JOIN warehouses w ON p.warehouse_id = w.id
    $where
    ORDER BY p.dye_name
");
$stmt->execute($params);
$products   = $stmt->fetchAll();

$warehouses = $pdo->query("SELECT * FROM warehouses ORDER BY name")->fetchAll();
$categories = $pdo->query("SELECT * FROM categories ORDER BY name")->fetchAll();

$msg_type = $msg_text = '';
if ($message) { [$msg_type, $msg_text] = explode(':', $message, 2); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Products - DyeStock</title>
    <link rel="stylesheet" href="assets/style.css">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <style>
        .filter-bar {
            display: flex; flex-wrap: wrap; gap: 10px; align-items: center;
            background: #fff; padding: 14px 18px;
            border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.06);
            margin-bottom: 18px;
        }
        .search-wrap { position: relative; flex: 1; min-width: 220px; }
        .search-wrap i { position: absolute; left: 12px; top: 50%; transform: translateY(-50%); color: #94a3b8; font-size: 0.85rem; pointer-events: none; }
        .search-wrap input {
            width: 100%; padding: 9px 14px 9px 36px;
            border: 1.5px solid #e2e8f0; border-radius: 9px;
            font-size: 0.9rem; font-family: inherit; color: #1e293b;
        }
        .search-wrap input:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59,130,246,0.1); }
        .filter-bar select {
            padding: 9px 14px; border: 1.5px solid #e2e8f0; border-radius: 9px;
            font-size: 0.88rem; font-family: inherit; color: #374151;
            background: #fff; cursor: pointer; min-width: 170px;
        }
        .filter-bar select:focus { outline: none; border-color: #3b82f6; }
        .btn-search {
            padding: 9px 20px; background: linear-gradient(135deg,#1e40af,#3b82f6);
            color: #fff; border: none; border-radius: 9px; font-size: 0.88rem;
            font-weight: 600; cursor: pointer; font-family: inherit;
            display: inline-flex; align-items: center; gap: 6px;
        }
        .btn-search:hover { opacity: 0.9; }
        .btn-clear {
            padding: 9px 14px; background: #f8fafc; border: 1.5px solid #e2e8f0;
            border-radius: 9px; font-size: 0.88rem; font-weight: 600;
            color: #64748b; cursor: pointer; font-family: inherit;
            text-decoration: none; display: inline-flex; align-items: center; gap: 5px;
        }
        .btn-clear:hover { background: #fee2e2; border-color: #fecaca; color: #dc2626; }
        .result-info {
            margin-left: auto; font-size: 0.83rem; color: #94a3b8;
            white-space: nowrap; font-weight: 500;
        }
        .highlight { background: #fef9c3; border-radius: 3px; padding: 0 2px; }
    </style>
</head>
<body>
<?php include 'includes/sidebar.php'; ?>
<main class="main-content">

    <header class="header">
        <div>
            <h1><i class="fas fa-box"></i> Products</h1>
            <p>Manage your dye inventory</p>
        </div>
        <button class="btn-primary" onclick="openModal('addModal')">
            <i class="fas fa-plus"></i> Add Product
        </button>
    </header>

    <?php if ($msg_text): ?>
        <div class="alert <?php echo $msg_type; ?>">
            <?php echo $msg_type==='success' ? '✅' : '❌'; ?> <?php echo htmlspecialchars($msg_text); ?>
        </div>
    <?php endif; ?>

    <!-- SEARCH & FILTER BAR -->
    <form method="GET" id="filterForm">
        <div class="filter-bar">

            <!-- Search by name / SKU -->
            <div class="search-wrap">
                <i class="fas fa-search"></i>
                <input type="text" name="search"
                       placeholder="Search product name or SKU..."
                       value="<?php echo htmlspecialchars($search); ?>"
                       id="searchInput">
            </div>

            <!-- Filter by warehouse -->
            <select name="warehouse">
                <option value="">All Warehouses</option>
                <?php foreach ($warehouses as $w): ?>
                <option value="<?php echo $w['id']; ?>" <?php echo $wh_filter==$w['id']?'selected':''; ?>>
                    <i class="fas fa-warehouse"></i> <?php echo htmlspecialchars($w['name']); ?>
                </option>
                <?php endforeach; ?>
            </select>

            <button type="submit" class="btn-search">
                <i class="fas fa-search"></i> Search
            </button>

            <?php if ($search || $wh_filter): ?>
            <a href="products.php" class="btn-clear">
                <i class="fas fa-times"></i> Clear
            </a>
            <?php endif; ?>

            <span class="result-info">
                <?php if ($search || $wh_filter): ?>
                    <i class="fas fa-filter" style="color:#3b82f6;"></i>
                    <?php echo count($products); ?> result(s) found
                <?php else: ?>
                    <?php echo count($products); ?> total products
                <?php endif; ?>
            </span>
        </div>
    </form>

    <!-- Active filter tags -->
    <?php if ($search || $wh_filter): ?>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:14px;">
        <?php if ($search): ?>
        <span style="background:#eff6ff;color:#1e40af;border:1px solid #bfdbfe;padding:4px 12px;border-radius:20px;font-size:0.82rem;font-weight:600;">
            <i class="fas fa-search"></i> "<?php echo htmlspecialchars($search); ?>"
        </span>
        <?php endif; ?>
        <?php if ($wh_filter): ?>
        <?php $wn = array_filter($warehouses, fn($w) => $w['id']==$wh_filter); $wname = reset($wn)['name'] ?? ''; ?>
        <span style="background:#f0fdf4;color:#166534;border:1px solid #bbf7d0;padding:4px 12px;border-radius:20px;font-size:0.82rem;font-weight:600;">
            <i class="fas fa-warehouse"></i> <?php echo htmlspecialchars($wname); ?>
        </span>
        <?php endif; ?>
    </div>
    <?php endif; ?>

    <div class="table-container">
        <table class="data-table">
            <thead>
                <tr>
                    <th>Dye Name</th>
                    <th>SKU</th>
                    <th>Category</th>
                    <th>Current Stock</th>
                    <th>Min Level</th>
                    <th>Warehouse</th>
                    <th>Status</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($products as $p): ?>
                <tr>
                    <td>
                        <strong>
                            <?php
                            // Highlight search term in name
                            $name = htmlspecialchars($p['dye_name']);
                            if ($search) {
                                $name = preg_replace('/(' . preg_quote(htmlspecialchars($search), '/') . ')/i',
                                    '<mark class="highlight">$1</mark>', $name);
                            }
                            echo $name;
                            ?>
                        </strong>
                    </td>
                    <td style="color:#94a3b8;font-size:0.85rem;">
                        <?php
                        $sku = htmlspecialchars($p['sku']);
                        if ($search) {
                            $sku = preg_replace('/(' . preg_quote(htmlspecialchars($search), '/') . ')/i',
                                '<mark class="highlight">$1</mark>', $sku);
                        }
                        echo $sku;
                        ?>
                    </td>
                    <td><?php echo htmlspecialchars($p['category_name'] ?? '-'); ?></td>
                    <td><strong><?php echo $p['current_stock']; ?> <?php echo $p['unit']; ?></strong></td>
                    <td><?php echo $p['min_stock_level']; ?> <?php echo $p['unit']; ?></td>
                    <td>
                        <i class="fas fa-warehouse" style="color:#94a3b8;margin-right:5px;font-size:0.8rem;"></i>
                        <?php echo htmlspecialchars($p['warehouse_name'] ?? '-'); ?>
                    </td>
                    <td>
                        <?php if ($p['current_stock'] <= $p['min_stock_level']): ?>
                            <span style="background:#fee2e2;color:#991b1b;padding:3px 10px;border-radius:20px;font-size:0.78rem;font-weight:600;">⚠ Low</span>
                        <?php else: ?>
                            <span style="background:#dcfce7;color:#166534;padding:3px 10px;border-radius:20px;font-size:0.78rem;font-weight:600;">✓ OK</span>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
                <?php if (!$products): ?>
                <tr>
                    <td colspan="7" style="text-align:center;color:#94a3b8;padding:3rem;">
                        <i class="fas fa-search" style="font-size:1.5rem;margin-bottom:10px;display:block;"></i>
                        No products found<?php echo $search ? " matching \"<strong>".htmlspecialchars($search)."</strong>\"" : ''; ?>.
                        <?php if ($search || $wh_filter): ?>
                        <br><a href="products.php" style="color:#3b82f6;font-size:0.88rem;">Clear filters</a>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endif; ?>
            </tbody>
        </table>
    </div>

    <!-- Add Product Modal -->
    <div id="addModal" class="modal">
        <div class="modal-content">
            <div class="modal-header">
                <h3><i class="fas fa-plus"></i> Add New Product</h3>
                <span class="close" onclick="closeModal('addModal')">&times;</span>
            </div>
            <form method="POST" style="padding:1.5rem;">
                <div class="form-group">
                    <label>Dye Name *</label>
                    <input type="text" name="dye_name" required>
                </div>
                <div class="form-group">
                    <label>SKU *</label>
                    <input type="text" name="sku" required placeholder="e.g. RB19-001">
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Category</label>
                        <select name="category_id">
                            <?php foreach ($categories as $c): ?>
                            <option value="<?php echo $c['id']; ?>"><?php echo htmlspecialchars($c['name']); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Unit</label>
                        <select name="unit">
                            <option value="kg">kg</option>
                            <option value="g">g</option>
                            <option value="L">L</option>
                        </select>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Min Stock Level</label>
                        <input type="number" name="min_stock_level" step="0.01" value="10">
                    </div>
                    <div class="form-group">
                        <label>Warehouse *</label>
                        <select name="warehouse_id" required>
                            <?php foreach ($warehouses as $wh): ?>
                            <option value="<?php echo $wh['id']; ?>"><?php echo htmlspecialchars($wh['name']); ?></option>
                            <?php endforeach; ?>
                        </select>
                    </div>
                </div>
                <div class="modal-actions">
                    <button type="button" class="btn-secondary" onclick="closeModal('addModal')">Cancel</button>
                    <button type="submit" name="add_product" class="btn-primary"><i class="fas fa-save"></i> Save Product</button>
                </div>
            </form>
        </div>
    </div>

</main>
<script src="assets/script.js"></script>
<script>
    // Auto-submit on Enter key in search box
    document.getElementById('searchInput').addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            document.getElementById('filterForm').submit();
        }
    });
</script>
</body>
</html>