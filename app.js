"use strict";

const PREFIX = "MNQR1.";
const ALGORITHM = "PBKDF2-SHA256-AES256GCM";
const ITERATIONS = 600000;
const BAD_PASSWORDS = new Set(["password", "123456", "bitcoin", "wallet", "mnemonic", "seedphrase"]);
const WORD_COUNTS = new Set([12, 15, 18, 21, 24]);

const $ = (selector) => document.querySelector(selector);
const wordIndex = new Map((window.BIP39_ENGLISH_WORDS || []).map((word, index) => [word, index]));

const elements = {
  supportError: $("#support-error"),
  encryptForm: $("#encrypt-form"),
  recoverForm: $("#recover-form"),
  mnemonic: $("#mnemonic"),
  encryptPassword: $("#encrypt-password"),
  confirmPassword: $("#confirm-password"),
  recoverPassword: $("#recover-password"),
  payloadOutput: $("#payload-output"),
  payloadInput: $("#payload-input"),
  recoveredMnemonic: $("#recovered-mnemonic"),
  encryptMessage: $("#encrypt-message"),
  recoverMessage: $("#recover-message"),
  qrOutput: $("#qr-output"),
  printQr: $("#print-qr"),
  printButton: $("#print-button"),
  copyPayloadButton: $("#copy-payload-button"),
  copyMnemonicButton: $("#copy-mnemonic-button")
};

function normalizeMnemonic(input) {
  return input.trim().toLowerCase().replace(/\s+/g, " ");
}

function bytesToBits(bytes) {
  return Array.from(bytes, (byte) => byte.toString(2).padStart(8, "0")).join("");
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function validateMnemonic(mnemonic) {
  const words = mnemonic.split(" ");
  if (!WORD_COUNTS.has(words.length)) throw new Error("Invalid mnemonic.");

  const indexes = words.map((word) => wordIndex.get(word));
  if (indexes.some((index) => index === undefined)) throw new Error("Invalid mnemonic.");

  const bits = indexes.map((index) => index.toString(2).padStart(11, "0")).join("");
  const checksumLength = words.length / 3;
  const entropyLength = bits.length - checksumLength;
  const entropyBits = bits.slice(0, entropyLength);
  const checksumBits = bits.slice(entropyLength);
  const entropy = new Uint8Array(entropyLength / 8);

  for (let i = 0; i < entropy.length; i += 1) {
    entropy[i] = parseInt(entropyBits.slice(i * 8, i * 8 + 8), 2);
  }

  const hashBits = bytesToBits(await sha256(entropy));
  if (checksumBits !== hashBits.slice(0, checksumLength)) throw new Error("Invalid mnemonic.");
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

async function deriveKey(password, salt, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

function base64urlEncode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64urlDecode(text) {
  if (typeof text !== "string" || text.length % 4 === 1 || !/^[A-Za-z0-9_-]*$/.test(text)) {
    throw new Error("Invalid QR payload.");
  }
  const padded = text.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(text.length / 4) * 4, "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function encodeEnvelope(envelope) {
  return PREFIX + base64urlEncode(new TextEncoder().encode(JSON.stringify(envelope)));
}

function decodeEnvelope(text) {
  const cleaned = text.replace(/\s+/g, "");
  if (!cleaned.startsWith(PREFIX)) throw new Error("Invalid QR payload.");

  let envelope;
  try {
    envelope = JSON.parse(new TextDecoder().decode(base64urlDecode(cleaned.slice(PREFIX.length))));
  } catch {
    throw new Error("Invalid QR payload.");
  }

  if (!envelope || Array.isArray(envelope) || typeof envelope !== "object") throw new Error("Invalid QR payload.");

  const keys = Object.keys(envelope).sort().join(",");
  if (keys !== "alg,ct,iter,iv,salt,v") throw new Error("Invalid QR payload.");
  if (envelope.v !== 1) throw new Error("Unsupported payload version.");
  if (envelope.alg !== ALGORITHM) throw new Error("Invalid QR payload.");
  if (!Number.isInteger(envelope.iter) || envelope.iter < ITERATIONS) throw new Error("Invalid QR payload.");

  return envelope;
}

async function encryptMnemonic(mnemonic, password) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveKey(password, salt, ITERATIONS);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: "AES-GCM", iv, tagLength: 128 },
    key,
    new TextEncoder().encode(mnemonic)
  ));

  return encodeEnvelope({
    v: 1,
    alg: ALGORITHM,
    iter: ITERATIONS,
    salt: base64urlEncode(salt),
    iv: base64urlEncode(iv),
    ct: base64urlEncode(ciphertext)
  });
}

async function decryptPayload(payload, password) {
  const envelope = decodeEnvelope(payload);
  const salt = base64urlDecode(envelope.salt);
  const iv = base64urlDecode(envelope.iv);
  const ciphertext = base64urlDecode(envelope.ct);

  if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 17) {
    throw new Error("Wrong password or corrupted QR.");
  }

  const key = await deriveKey(password, salt, envelope.iter);
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128 }, key, ciphertext);
  } catch {
    throw new Error("Wrong password or corrupted QR.");
  }

  const mnemonic = new TextDecoder().decode(plaintext);
  await validateMnemonic(mnemonic);
  return mnemonic;
}

function validatePassword(password, confirmation) {
  if (password.length < 12) throw new Error("Password is too short.");
  if (BAD_PASSWORDS.has(password.trim().toLowerCase())) throw new Error("Password is too weak.");
  if (confirmation !== undefined && password !== confirmation) throw new Error("Passwords do not match.");
}

function setMessage(node, text, type = "") {
  node.textContent = text;
  node.className = `message ${type}`.trim();
}

function renderQR(text) {
  const qr = qrcode(0, "M");
  qr.addData(text);
  qr.make();
  const svg = qr.createSvgTag(5, 2, "Encrypted mnemonic QR", "Encrypted mnemonic QR");
  elements.qrOutput.classList.remove("qr-placeholder");
  elements.qrOutput.innerHTML = svg;
  elements.printQr.innerHTML = svg;
}

function clearSecrets() {
  elements.mnemonic.value = "";
  elements.encryptPassword.value = "";
  elements.confirmPassword.value = "";
  elements.recoverPassword.value = "";
  elements.payloadInput.value = "";
  elements.payloadOutput.value = "";
  elements.recoveredMnemonic.value = "";
  elements.qrOutput.className = "qr-frame qr-placeholder";
  elements.qrOutput.textContent = "QR appears here after encryption.";
  elements.printQr.textContent = "";
  elements.printButton.disabled = true;
  elements.copyPayloadButton.disabled = true;
  elements.copyMnemonicButton.disabled = true;
  setMessage(elements.encryptMessage, "");
  setMessage(elements.recoverMessage, "");
}

function setBusy(form, busy) {
  for (const control of form.querySelectorAll("button, input, textarea")) {
    control.disabled = busy;
  }
}

async function copyText(text, messageNode) {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    setMessage(messageNode, "Copied.", "success");
  } catch {
    setMessage(messageNode, "Copy failed. Select the text and copy it manually.", "error");
  }
}

function switchTab(name) {
  for (const tab of document.querySelectorAll(".tab")) {
    const active = tab.dataset.tab === name;
    tab.classList.toggle("active", active);
    tab.setAttribute("aria-selected", String(active));
  }
  for (const panel of document.querySelectorAll(".panel")) {
    const active = panel.id === `${name}-panel`;
    panel.classList.toggle("active", active);
    panel.hidden = !active;
  }
}

async function handleEncrypt(event) {
  event.preventDefault();
  setBusy(elements.encryptForm, true);
  setMessage(elements.encryptMessage, "Encrypting locally...");

  try {
    const mnemonic = normalizeMnemonic(elements.mnemonic.value);
    validatePassword(elements.encryptPassword.value, elements.confirmPassword.value);
    await validateMnemonic(mnemonic);
    const payload = await encryptMnemonic(mnemonic, elements.encryptPassword.value);
    elements.payloadOutput.value = payload;
    renderQR(payload);
    elements.printButton.disabled = false;
    elements.copyPayloadButton.disabled = false;
    setMessage(elements.encryptMessage, "Encrypted QR payload generated.", "success");
  } catch (error) {
    setMessage(elements.encryptMessage, error.message || "Invalid mnemonic.", "error");
  } finally {
    setBusy(elements.encryptForm, false);
  }
}

async function handleRecover(event) {
  event.preventDefault();
  setBusy(elements.recoverForm, true);
  elements.recoveredMnemonic.value = "";
  elements.copyMnemonicButton.disabled = true;
  setMessage(elements.recoverMessage, "Decrypting locally...");

  try {
    const password = elements.recoverPassword.value;
    if (!password) throw new Error("Password is too short.");
    const mnemonic = await decryptPayload(elements.payloadInput.value, password);
    elements.recoveredMnemonic.value = mnemonic;
    elements.copyMnemonicButton.disabled = false;
    setMessage(elements.recoverMessage, "Mnemonic recovered.", "success");
  } catch (error) {
    const safeMessage = error.message === "Unsupported payload version." || error.message === "Invalid QR payload."
      ? error.message
      : "Wrong password or corrupted QR.";
    setMessage(elements.recoverMessage, safeMessage, "error");
  } finally {
    setBusy(elements.recoverForm, false);
  }
}

function init() {
  if (!window.crypto || !crypto.subtle) {
    elements.supportError.textContent = "This browser does not support Web Crypto.";
    elements.supportError.classList.remove("hidden");
    for (const control of document.querySelectorAll("button, input, textarea")) control.disabled = true;
    return;
  }

  if (wordIndex.size !== 2048 || typeof qrcode !== "function") {
    elements.supportError.textContent = "Required local assets failed to load.";
    elements.supportError.classList.remove("hidden");
    for (const control of document.querySelectorAll("button, input, textarea")) control.disabled = true;
    return;
  }

  elements.encryptForm.addEventListener("submit", handleEncrypt);
  elements.recoverForm.addEventListener("submit", handleRecover);
  elements.printButton.addEventListener("click", () => window.print());
  elements.copyPayloadButton.addEventListener("click", () => copyText(elements.payloadOutput.value, elements.encryptMessage));
  elements.copyMnemonicButton.addEventListener("click", () => copyText(elements.recoveredMnemonic.value, elements.recoverMessage));

  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => switchTab(tab.dataset.tab));
  }
  for (const button of document.querySelectorAll("[data-clear]")) {
    button.addEventListener("click", clearSecrets);
  }
}

init();
