let productCatalog = [];
let cart = [];

document.addEventListener("DOMContentLoaded", () => {
  if (!document.getElementById("shop-shell")) return;
  initializeShop().catch((error) => {
    console.error("Init shop error:", error);
    const el = document.getElementById("shop-msg");
    if (el) {
      el.textContent = "商城页面初始化失败，请刷新后重试。";
      el.className = "message error";
    }
  });
});

async function initializeShop() {
  bindShopEvents();
  await loadProducts();
  await loadOrders();
  renderCart();
}

function bindShopEvents() {
  const orderForm = document.getElementById("orderForm");
  if (orderForm) orderForm.addEventListener("submit", submitOrder);

  const productGrid = document.getElementById("productGrid");
  if (productGrid) {
    productGrid.addEventListener("click", (event) => {
      const button = event.target.closest("[data-add-product]");
      if (!button) return;
      addToCart(Number(button.dataset.addProduct));
    });
  }

  const cartList = document.getElementById("cartList");
  if (cartList) {
    cartList.addEventListener("click", (event) => {
      const actionButton = event.target.closest("[data-cart-action]");
      if (!actionButton) return;
      const productId = Number(actionButton.dataset.productId);
      const action = actionButton.dataset.cartAction;
      if (action === "plus") updateCartQuantity(productId, 1);
      if (action === "minus") updateCartQuantity(productId, -1);
      if (action === "remove") removeFromCart(productId);
    });
  }

  const orderList = document.getElementById("orderList");
  if (orderList) {
    orderList.addEventListener("click", async (event) => {
      const button = event.target.closest("[data-pay-order]");
      if (!button) return;
      await confirmPayment(Number(button.dataset.payOrder));
    });
  }
}

async function fetchJson(url, options) {
  const res = await fetch(url, options);
  const data = await res.json();
  if (!res.ok || !data.success) {
    throw new Error(data.message || "请求失败。");
  }
  return data;
}

async function loadProducts() {
  const data = await fetchJson("/api/shop/products");
  productCatalog = data.products;
  renderProducts();
  renderMetrics();
}

async function loadOrders() {
  const data = await fetchJson("/api/shop/orders");
  renderOrders(data.orders);
}

function renderMetrics() {
  const totalProducts = document.getElementById("metricProducts");
  const totalStock = document.getElementById("metricStock");
  const totalCategories = document.getElementById("metricCategories");
  if (!totalProducts || !totalStock || !totalCategories) return;

  totalProducts.textContent = String(productCatalog.length);
  totalStock.textContent = String(productCatalog.reduce((sum, product) => sum + product.stock, 0));
  totalCategories.textContent = String(new Set(productCatalog.map((product) => product.category)).size);
}

function renderProducts() {
  const grid = document.getElementById("productGrid");
  if (!grid) return;

  grid.innerHTML = productCatalog.map((product) => `
    <article class="product-card">
      <div class="product-card-top">
        <span class="product-category">${escapeHtml(product.category)}</span>
        ${product.badge ? `<span class="product-badge">${escapeHtml(product.badge)}</span>` : ""}
      </div>
      <h3>${escapeHtml(product.name)}</h3>
      <p class="product-desc">${escapeHtml(product.description)}</p>
      <div class="product-meta">
        <strong>¥${product.price.toFixed(2)}</strong>
        <span>库存 ${product.stock}</span>
      </div>
      <button class="product-btn" data-add-product="${product.id}" ${product.stock <= 0 ? "disabled" : ""}>
        ${product.stock <= 0 ? "暂时缺货" : "加入购物车"}
      </button>
    </article>
  `).join("");
}

function findCartItem(productId) {
  return cart.find((item) => item.productId === productId);
}

function addToCart(productId) {
  const product = productCatalog.find((item) => item.id === productId);
  if (!product || product.stock <= 0) return;

  const existing = findCartItem(productId);
  if (existing) {
    if (existing.quantity < product.stock) {
      existing.quantity += 1;
    }
  } else {
    cart.push({
      productId,
      quantity: 1,
    });
  }

  renderCart();
  setShopMessage("商品已加入购物车。", "success");
}

function updateCartQuantity(productId, delta) {
  const product = productCatalog.find((item) => item.id === productId);
  const existing = findCartItem(productId);
  if (!product || !existing) return;

  existing.quantity = Math.max(1, Math.min(product.stock, existing.quantity + delta));
  renderCart();
}

function removeFromCart(productId) {
  cart = cart.filter((item) => item.productId !== productId);
  renderCart();
}

function getCartDetailedItems() {
  return cart.map((item) => {
    const product = productCatalog.find((p) => p.id === item.productId);
    return {
      ...item,
      product,
      subtotal: product ? product.price * item.quantity : 0,
    };
  }).filter((item) => item.product);
}

function renderCart() {
  const list = document.getElementById("cartList");
  const totalEl = document.getElementById("cartTotal");
  const countEl = document.getElementById("cartCount");
  if (!list || !totalEl || !countEl) return;

  const items = getCartDetailedItems();
  countEl.textContent = String(items.reduce((sum, item) => sum + item.quantity, 0));
  totalEl.textContent = `¥${items.reduce((sum, item) => sum + item.subtotal, 0).toFixed(2)}`;

  if (!items.length) {
    list.innerHTML = `<div class="empty-state">购物车为空。请先从商品区选择商品。</div>`;
    return;
  }

  list.innerHTML = items.map((item) => `
    <div class="cart-item">
      <div>
        <strong>${escapeHtml(item.product.name)}</strong>
        <p>¥${item.product.price.toFixed(2)} / 件</p>
      </div>
      <div class="cart-actions">
        <button type="button" data-cart-action="minus" data-product-id="${item.productId}">-</button>
        <span>${item.quantity}</span>
        <button type="button" data-cart-action="plus" data-product-id="${item.productId}">+</button>
        <button type="button" data-cart-action="remove" data-product-id="${item.productId}">移除</button>
      </div>
    </div>
  `).join("");
}

async function submitOrder(event) {
  event.preventDefault();
  const items = getCartDetailedItems();
  if (!items.length) {
    setShopMessage("请先添加商品到购物车。", "warning");
    return;
  }

  const shippingName = document.getElementById("shippingName").value.trim();
  const shippingPhone = document.getElementById("shippingPhone").value.trim();
  const shippingAddress = document.getElementById("shippingAddress").value.trim();
  const note = document.getElementById("orderNote").value.trim();

  try {
    const data = await fetchJson("/api/shop/orders", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        shippingName,
        shippingPhone,
        shippingAddress,
        note,
        items: items.map((item) => ({
          productId: item.productId,
          quantity: item.quantity,
        })),
      }),
    });

    cart = [];
    document.getElementById("orderForm").reset();
    setShopMessage(`${data.message} 订单号：${data.orderNo}`, "success");
    await loadProducts();
    await loadOrders();
    renderCart();
  } catch (error) {
    setShopMessage(error.message, "error");
  }
}

async function confirmPayment(orderId) {
  try {
    const data = await fetchJson(`/api/shop/orders/${orderId}/pay`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    setShopMessage(data.message, "success");
    await loadOrders();
  } catch (error) {
    setShopMessage(error.message, "error");
  }
}

function renderOrders(orders) {
  const list = document.getElementById("orderList");
  if (!list) return;

  if (!orders.length) {
    list.innerHTML = `<div class="empty-state">暂无订单。下单后可在这里查看待付款确认和交易结果。</div>`;
    return;
  }

  list.innerHTML = orders.map((order) => `
    <article class="order-card">
      <div class="order-head">
        <div>
          <strong>${escapeHtml(order.orderNo)}</strong>
          <span>${new Date(order.createdAt).toLocaleString("zh-CN")}</span>
        </div>
        <span class="order-status">${escapeHtml(order.status)}</span>
      </div>
      <div class="order-items">
        ${order.items.map((item) => `
          <div class="order-item-row">
            <span>${escapeHtml(item.productName)} x ${item.quantity}</span>
            <span>¥${item.subtotal.toFixed(2)}</span>
          </div>
        `).join("")}
      </div>
      <div class="order-foot">
        <div>
          <p>收货人：${escapeHtml(order.shippingName)}</p>
          <p>地址：${escapeHtml(order.shippingAddress)}</p>
        </div>
        <div class="order-action">
          <strong>合计 ¥${order.totalAmount.toFixed(2)}</strong>
          ${order.status === "待付款确认" ? `<button class="product-btn" data-pay-order="${order.id}">模拟付款确认</button>` : ""}
        </div>
      </div>
    </article>
  `).join("");
}

function setShopMessage(message, type) {
  const el = document.getElementById("shop-msg");
  if (!el) return;
  el.textContent = message;
  el.className = `message ${type || ""}`.trim();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}
