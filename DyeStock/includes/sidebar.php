<?php $current_page = basename($_SERVER['PHP_SELF']); ?>
<aside class="sidebar">
    <div class="sidebar-header">
        <h2>🧵 DyeStock</h2>
        <p style="font-size:0.8rem;opacity:0.7;margin-top:4px;">Textile Inventory</p>
    </div>

    <?php if (isManager()): ?>
    <!-- MANAGER ROLE BADGE -->
    <div style="margin:0 12px 6px;padding:8px 14px;background:rgba(255,255,255,0.12);border-radius:8px;display:flex;align-items:center;gap:8px;">
        <i class="fas fa-user-tie" style="color:#fbbf24;font-size:0.85rem;"></i>
        <span style="font-size:0.8rem;font-weight:600;color:#fff;">Inventory Manager</span>
    </div>
    <?php else: ?>
    <!-- STAFF ROLE BADGE -->
    <div style="margin:0 12px 6px;padding:8px 14px;background:rgba(255,255,255,0.12);border-radius:8px;display:flex;align-items:center;gap:8px;">
        <i class="fas fa-hard-hat" style="color:#34d399;font-size:0.85rem;"></i>
        <span style="font-size:0.8rem;font-weight:600;color:#fff;">Warehouse Staff</span>
    </div>
    <?php endif; ?>

    <nav class="sidebar-nav">

        <!-- BOTH ROLES -->
        <a href="dashboard.php" class="<?php echo $current_page=='dashboard.php' ? 'active':''; ?>">
            <i class="fas fa-chart-bar" style="margin-right:12px;"></i> Dashboard
        </a>

        <?php if (isManager()): ?>
        <!-- MANAGER ONLY -->
        <div style="padding:8px 20px 4px;font-size:0.7rem;font-weight:700;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:0.08em;">
            Stock Management
        </div>
        <a href="products.php" class="<?php echo $current_page=='products.php' ? 'active':''; ?>">
            <i class="fas fa-box" style="margin-right:12px;"></i> Products
        </a>
        <a href="receipts.php" class="<?php echo $current_page=='receipts.php' ? 'active':''; ?>">
            <i class="fas fa-download" style="margin-right:12px;"></i> Receipts
        </a>
        <a href="deliveries.php" class="<?php echo $current_page=='deliveries.php' ? 'active':''; ?>">
            <i class="fas fa-upload" style="margin-right:12px;"></i> Deliveries
        </a>
        <a href="transfers.php" class="<?php echo $current_page=='transfers.php' ? 'active':''; ?>">
            <i class="fas fa-exchange-alt" style="margin-right:12px;"></i> Transfers
        </a>
        <a href="adjustment.php" class="<?php echo $current_page=='adjustment.php' ? 'active':''; ?>">
            <i class="fas fa-balance-scale" style="margin-right:12px;"></i> Adjustments
        </a>

        <div style="padding:8px 20px 4px;font-size:0.7rem;font-weight:700;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:0.08em;">
            Reports
        </div>
        <a href="history.php" class="<?php echo $current_page=='history.php' ? 'active':''; ?>">
            <i class="fas fa-history" style="margin-right:12px;"></i> History
        </a>

        <?php else: ?>
        <!-- STAFF ONLY -->
        <div style="padding:8px 20px 4px;font-size:0.7rem;font-weight:700;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:0.08em;">
            Warehouse Tasks
        </div>
        <a href="receipts.php" class="<?php echo $current_page=='receipts.php' ? 'active':''; ?>">
            <i class="fas fa-download" style="margin-right:12px;"></i> Receive Stock
        </a>
        <a href="deliveries.php" class="<?php echo $current_page=='deliveries.php' ? 'active':''; ?>">
            <i class="fas fa-upload" style="margin-right:12px;"></i> Dispatch / Picking
        </a>
        <a href="transfers.php" class="<?php echo $current_page=='transfers.php' ? 'active':''; ?>">
            <i class="fas fa-exchange-alt" style="margin-right:12px;"></i> Transfers / Shelving
        </a>
        <?php endif; ?>

        <div style="padding:8px 20px 4px;font-size:0.7rem;font-weight:700;color:rgba(255,255,255,0.4);text-transform:uppercase;letter-spacing:0.08em;">
            Account
        </div>
        <a href="logout.php">
            <i class="fas fa-sign-out-alt" style="margin-right:12px;"></i> Logout
        </a>

    </nav>
</aside>