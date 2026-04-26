const KEY_DB_NAME = "secure-auth-rsa-db";
const KEY_STORE_NAME = "private_keys";

document.addEventListener("DOMContentLoaded", () => {
  const loginForm = document.getElementById("loginForm");
  if (loginForm) loginForm.addEventListener("submit", handleLogin);

  const registerForm = document.getElementById("registerForm");
  if (registerForm) registerForm.addEventListener("submit", handleRegister);

  const recoveryRequestForm = document.getElementById("recoveryRequestForm");
  if (recoveryRequestForm) recoveryRequestForm.addEventListener("submit", handleRecoveryRequest);

  const recoveryVerifyForm = document.getElementById("recoveryVerifyForm");
  if (recoveryVerifyForm) recoveryVerifyForm.addEventListener("submit", handleRecoveryVerify);

  const toggleRecoveryButton = document.getElementById("toggleRecoveryBtn");
  if (toggleRecoveryButton) toggleRecoveryButton.addEventListener("click", toggleRecoveryPanel);

  const regPasswordInput = document.getElementById("reg-password");
  if (regPasswordInput) regPasswordInput.addEventListener("input", updatePasswordStrength);

  const logoutButton = document.getElementById("logoutBtn");
  if (logoutButton) logoutButton.addEventListener("click", handleLogout);

  const dashboardUsername = document.getElementById("session-username");
  if (dashboardUsername) loadSession();
});

function updatePasswordStrength() {
  const password = document.getElementById("reg-password").value;
  const lengthCheck = document.getElementById("length-check");
  const caseCheck = document.getElementById("case-check");
  const numberCheck = document.getElementById("number-check");
  const specialCheck = document.getElementById("special-check");

  if (password.length >= 10) lengthCheck.classList.add("valid"); else lengthCheck.classList.remove("valid");
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) caseCheck.classList.add("valid"); else caseCheck.classList.remove("valid");
  if (/\d/.test(password)) numberCheck.classList.add("valid"); else numberCheck.classList.remove("valid");
  if (/[!@#$%^&*()_+\-=[\]{};':"\\|,.<>\/?]/.test(password)) specialCheck.classList.add("valid"); else specialCheck.classList.remove("valid");
}

function setMessage(element, text, type) {
  if (!element) return;
  element.textContent = text;
  element.className = `message ${type || ""}`.trim();
}

function ensureCryptoSupport() {
  if (!window.crypto || !window.crypto.subtle || !window.indexedDB) {
    throw new Error("当前浏览器不支持 Web Crypto API 或 IndexedDB，无法完成 RSA 认证。");
  }
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = window.atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

function formatPem(base64, label) {
  const wrapped = base64.match(/.{1,64}/g)?.join("\n") || base64;
  return `-----BEGIN ${label}-----\n${wrapped}\n-----END ${label}-----`;
}

function parsePem(pem, label) {
  return pem
    .replace(`-----BEGIN ${label}-----`, "")
    .replace(`-----END ${label}-----`, "")
    .replace(/\s+/g, "");
}

async function generateRsaKeyPair() {
  ensureCryptoSupport();
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"]
  );

  const publicKeyBuffer = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
  const privateKeyBuffer = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);

  return {
    publicKeyPem: formatPem(arrayBufferToBase64(publicKeyBuffer), "PUBLIC KEY"),
    privateKeyPem: formatPem(arrayBufferToBase64(privateKeyBuffer), "PRIVATE KEY"),
  };
}

async function importPrivateKey(privateKeyPem) {
  const privateKeyBase64 = parsePem(privateKeyPem, "PRIVATE KEY");
  return window.crypto.subtle.importKey(
    "pkcs8",
    base64ToArrayBuffer(privateKeyBase64),
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );
}

async function signChallenge(privateKeyPem, challenge) {
  const privateKey = await importPrivateKey(privateKeyPem);
  const signature = await window.crypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    privateKey,
    new TextEncoder().encode(challenge)
  );
  return arrayBufferToBase64(signature);
}

function openKeyDatabase() {
  return new Promise((resolve, reject) => {
    const request = window.indexedDB.open(KEY_DB_NAME, 1);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(KEY_STORE_NAME)) {
        db.createObjectStore(KEY_STORE_NAME, { keyPath: "username" });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(new Error("无法打开本地密钥库。"));
  });
}

async function savePrivateKey(username, privateKeyPem) {
  const db = await openKeyDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_STORE_NAME, "readwrite");
    tx.objectStore(KEY_STORE_NAME).put({ username, privateKeyPem, savedAt: new Date().toISOString() });
    tx.oncomplete = () => {
      db.close();
      resolve();
    };
    tx.onerror = () => {
      db.close();
      reject(new Error("无法将私钥保存到本地。"));
    };
  });
}

async function getPrivateKey(username) {
  const db = await openKeyDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(KEY_STORE_NAME, "readonly");
    const request = tx.objectStore(KEY_STORE_NAME).get(username);
    request.onsuccess = () => {
      db.close();
      resolve(request.result?.privateKeyPem || null);
    };
    request.onerror = () => {
      db.close();
      reject(new Error("读取本地私钥失败。"));
    };
  });
}

async function postJson(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json();
  return { response, data };
}

function toggleRecoveryPanel() {
  const panel = document.getElementById("recoveryPanel");
  const button = document.getElementById("toggleRecoveryBtn");
  if (!panel || !button) return;

  const expanded = panel.classList.toggle("hidden");
  button.textContent = expanded ? "新设备邮箱恢复" : "收起邮箱恢复";
}

async function handleRegister(event) {
  event.preventDefault();
  const username = document.getElementById("reg-username").value.trim();
  const email = document.getElementById("reg-email").value.trim().toLowerCase();
  const password = document.getElementById("reg-password").value;
  const confirmPassword = document.getElementById("confirm-password").value;
  const msgEl = document.getElementById("reg-msg");

  setMessage(msgEl, "");

  if (password !== confirmPassword) {
    setMessage(msgEl, "两次输入的密码不一致！", "error");
    return;
  }

  const isLengthValid = password.length >= 10;
  const charTypeCount = [/[a-z]/, /[A-Z]/, /\d/, /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>\/?]/]
    .reduce((count, regex) => count + (regex.test(password) ? 1 : 0), 0);

  if (!username || !email) {
    setMessage(msgEl, "请输入用户名和邮箱。", "warning");
    return;
  }

  if (!isLengthValid || charTypeCount < 4) {
    setMessage(msgEl, "密码强度不足，请满足全部要求。", "error");
    return;
  }

  try {
    setMessage(msgEl, "正在本地生成 RSA 密钥对，请稍候...", "info");
    const { publicKeyPem, privateKeyPem } = await generateRsaKeyPair();

    setMessage(msgEl, "正在提交注册信息并绑定邮箱、公钥...", "info");
    const { response, data } = await postJson("/api/auth/register", {
      username,
      email,
      password,
      publicKey: publicKeyPem,
    });

    if (!response.ok || !data.success) {
      setMessage(msgEl, data.message || "注册失败。", "error");
      return;
    }

    await savePrivateKey(username, privateKeyPem);
    setMessage(msgEl, "注册成功，本地私钥保存完成，正在进入控制台...", "success");
    setTimeout(() => { window.location.href = "dashboard.html"; }, 900);
  } catch (error) {
    console.error("注册失败:", error);
    setMessage(msgEl, error.message || "网络或服务器错误。", "error");
  }
}

async function handleLogin(event) {
  event.preventDefault();
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value;
  const msgEl = document.getElementById("login-msg");

  setMessage(msgEl, "");

  if (!username || !password) {
    setMessage(msgEl, "用户名和密码不能为空。", "warning");
    return;
  }

  try {
    setMessage(msgEl, "正在验证密码...", "info");
    const { response, data } = await postJson("/api/auth/login", { username, password });

    if (!response.ok || !data.success) {
      setMessage(msgEl, data.message || "登录失败。", "error");
      return;
    }

    setMessage(msgEl, "密码正确，正在读取本地 RSA 私钥...", "info");
    const privateKeyPem = await getPrivateKey(username);
    if (!privateKeyPem) {
      setMessage(msgEl, "当前设备没有该账号私钥，请使用下方邮箱恢复并重新绑定新设备。", "warning");
      const recoveryPanel = document.getElementById("recoveryPanel");
      const toggleButton = document.getElementById("toggleRecoveryBtn");
      if (recoveryPanel && toggleButton && recoveryPanel.classList.contains("hidden")) {
        recoveryPanel.classList.remove("hidden");
        toggleButton.textContent = "收起邮箱恢复";
      }
      return;
    }

    setMessage(msgEl, "正在使用本地私钥签名挑战码...", "info");
    const signature = await signChallenge(privateKeyPem, data.challenge);

    setMessage(msgEl, "正在向服务器提交签名验证...", "info");
    const verification = await postJson("/api/auth/verify-signature", {
      username,
      challengeId: data.challengeId,
      challenge: data.challenge,
      signature,
    });

    if (verification.response.ok && verification.data.success) {
      setMessage(msgEl, "双因子认证成功，正在跳转...", "success");
      window.location.href = "dashboard.html";
      return;
    }

    setMessage(msgEl, verification.data.message || "RSA 验签失败。", "error");
  } catch (error) {
    console.error("登录失败:", error);
    setMessage(msgEl, error.message || "网络或服务器错误，请稍后再试。", "error");
  }
}

async function handleRecoveryRequest(event) {
  event.preventDefault();
  const username = document.getElementById("recovery-username").value.trim();
  const password = document.getElementById("recovery-password").value;
  const msgEl = document.getElementById("recovery-msg");

  setMessage(msgEl, "");

  if (!username || !password) {
    setMessage(msgEl, "请输入用户名和密码以申请邮箱恢复。", "warning");
    return;
  }

  try {
    setMessage(msgEl, "正在校验账号并发送邮箱验证码...", "info");
    const { response, data } = await postJson("/api/auth/request-email-recovery", {
      username,
      password,
    });

    if (!response.ok || !data.success) {
      setMessage(msgEl, data.message || "邮箱恢复申请失败。", "error");
      return;
    }

    document.getElementById("verify-username").value = username;
    setMessage(msgEl, data.message || "验证码已发送。", "success");
  } catch (error) {
    console.error("邮箱恢复申请失败:", error);
    setMessage(msgEl, error.message || "网络或服务器错误。", "error");
  }
}

async function handleRecoveryVerify(event) {
  event.preventDefault();
  const username = document.getElementById("verify-username").value.trim();
  const code = document.getElementById("verify-code").value.trim();
  const msgEl = document.getElementById("recovery-msg");

  setMessage(msgEl, "");

  if (!username || !code) {
    setMessage(msgEl, "请输入用户名和邮箱验证码。", "warning");
    return;
  }

  try {
    setMessage(msgEl, "正在为当前设备生成新的 RSA 密钥对...", "info");
    const { publicKeyPem, privateKeyPem } = await generateRsaKeyPair();

    setMessage(msgEl, "正在验证邮箱并绑定新的设备公钥...", "info");
    const { response, data } = await postJson("/api/auth/verify-email-recovery", {
      username,
      code,
      newPublicKey: publicKeyPem,
    });

    if (!response.ok || !data.success) {
      setMessage(msgEl, data.message || "邮箱恢复失败。", "error");
      return;
    }

    await savePrivateKey(username, privateKeyPem);
    setMessage(msgEl, "邮箱验证成功，新设备 RSA 公钥已绑定，正在进入控制台...", "success");
    setTimeout(() => { window.location.href = "dashboard.html"; }, 900);
  } catch (error) {
    console.error("邮箱恢复失败:", error);
    setMessage(msgEl, error.message || "网络或服务器错误。", "error");
  }
}

async function loadSession() {
  const usernameEl = document.getElementById("session-username");
  const createdAtEl = document.getElementById("session-created-at");
  const rsaStatusEl = document.getElementById("session-rsa-status");
  const emailEl = document.getElementById("session-email");
  const msgEl = document.getElementById("dashboard-msg");

  try {
    const res = await fetch("/api/auth/session");
    const data = await res.json();

    if (!res.ok || !data.success) {
      window.location.href = "index.html";
      return;
    }

    usernameEl.textContent = data.user.username;
    createdAtEl.textContent = new Date(data.user.createdAt).toLocaleString("zh-CN");
    if (emailEl) {
      emailEl.textContent = data.user.email || "未绑定";
    }
    if (rsaStatusEl) {
      rsaStatusEl.textContent = data.user.rsaEnabled ? "已启用" : "未启用";
    }
    setMessage(msgEl, "当前登录支持密码 + RSA 私钥签名；丢失私钥时可通过邮箱验证在新设备重绑。", "success");
  } catch (error) {
    console.error("读取会话失败:", error);
    setMessage(msgEl, "会话加载失败，请重新登录。", "error");
  }
}

async function handleLogout() {
  const msgEl = document.getElementById("dashboard-msg");

  try {
    const res = await fetch("/api/auth/logout", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    const data = await res.json();
    if (res.ok && data.success) {
      window.location.href = "index.html";
      return;
    }
    setMessage(msgEl, data.message || "退出失败，请稍后重试。", "error");
  } catch (error) {
    console.error("退出失败:", error);
    setMessage(msgEl, "网络异常，暂时无法退出。", "error");
  }
}
