"use strict";

const PREFIX = "MNQR1.";
const ALGORITHM = "PBKDF2-SHA256-AES256GCM";
const ITERATIONS = 600000;
const CHECK_TEXT = "MNQR-CHECK";
const BAD_PASSWORDS = new Set(["password", "123456", "bitcoin", "wallet", "mnemonic", "seedphrase"]);
const WORD_COUNTS = new Set([12, 15, 18, 21, 24]);

const $ = (selector) => document.querySelector(selector);
const wordIndex = new Map((window.BIP39_ENGLISH_WORDS || []).map((word, index) => [word, index]));
const qrDecoder = window.jsQR;

const elements = {
  supportError: $("#support-error"),
  encryptForm: $("#encrypt-form"),
  recoverForm: $("#recover-form"),
  checkForm: $("#check-form"),
  mnemonic: $("#mnemonic"),
  encryptPassword: $("#encrypt-password"),
  confirmPassword: $("#confirm-password"),
  recoverPassword: $("#recover-password"),
  checkPassword: $("#check-password"),
  payloadOutput: $("#payload-output"),
  fingerprintOutput: $("#fingerprint-output"),
  payloadInput: $("#payload-input"),
  checkPayloadInput: $("#check-payload-input"),
  recoveredMnemonic: $("#recovered-mnemonic"),
  encryptMessage: $("#encrypt-message"),
  recoverMessage: $("#recover-message"),
  checkMessage: $("#check-message"),
  checkStatus: $("#check-status"),
  checkFingerprintOutput: $("#check-fingerprint-output"),
  qrOutput: $("#qr-output"),
  printQr: $("#print-qr"),
  printFingerprint: $("#print-fingerprint"),
  printButton: $("#print-button"),
  copyPayloadButton: $("#copy-payload-button"),
  copyMnemonicButton: $("#copy-mnemonic-button")
};

let scannerStream = null;
let scannerFrameId = null;
let scannerBusy = false;
let activeScanner = null;

function wipeBytes(value) {
  if (!value) return;
  if (value instanceof ArrayBuffer) {
    new Uint8Array(value).fill(0);
    return;
  }
  if (ArrayBuffer.isView(value)) value.fill(0);
}

function normalizeMnemonic(input) {
  return input.trim().toLowerCase().replace(/\s+/g, " ");
}

function bytesToBits(bytes) {
  return Array.from(bytes, (byte) => byte.toString(2).padStart(8, "0")).join("");
}

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
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

async function deriveKey(passwordBytes, salt, iterations) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    passwordBytes,
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

function envelopeKeys(envelope) {
  return Object.keys(envelope).sort().join(",");
}

function decodeEnvelope(text) {
  if (typeof text !== "string") throw new Error("Invalid QR payload.");
  const cleaned = text.replace(/\s+/g, "");
  if (!cleaned.startsWith(PREFIX)) throw new Error("Invalid QR payload.");

  let envelope;
  try {
    envelope = JSON.parse(new TextDecoder().decode(base64urlDecode(cleaned.slice(PREFIX.length))));
  } catch {
    throw new Error("Invalid QR payload.");
  }

  if (!envelope || Array.isArray(envelope) || typeof envelope !== "object") throw new Error("Invalid QR payload.");

  if (envelopeKeys(envelope) !== "alg,chk,chkIv,ct,fp,iter,iv,salt") throw new Error("Invalid QR payload.");
  if (envelope.alg !== ALGORITHM) throw new Error("Invalid QR payload.");
  if (!Number.isInteger(envelope.iter) || envelope.iter < ITERATIONS) throw new Error("Invalid QR payload.");

  return envelope;
}

function fingerprintInput(envelope) {
  return JSON.stringify({
    alg: envelope.alg,
    iter: envelope.iter,
    salt: envelope.salt,
    iv: envelope.iv,
    ct: envelope.ct,
    chkIv: envelope.chkIv,
    chk: envelope.chk
  });
}

async function computeFingerprint(envelope) {
  let hash;
  let fingerprintBytes;
  try {
    hash = await sha256(new TextEncoder().encode(fingerprintInput(envelope)));
    fingerprintBytes = hash.slice(0, 8);
    return bytesToHex(fingerprintBytes).match(/.{1,4}/g).join("-");
  } finally {
    wipeBytes(hash);
    wipeBytes(fingerprintBytes);
  }
}

async function assertFingerprint(envelope) {
  if (typeof envelope.fp !== "string") throw new Error("Invalid QR payload.");
  if (await computeFingerprint(envelope) !== envelope.fp) throw new Error("Wrong password or corrupted QR.");
}

async function encryptMnemonic(mnemonic, password) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const chkIv = randomBytes(12);
  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(password);
  const mnemonicBytes = encoder.encode(mnemonic);
  const checkBytes = encoder.encode(CHECK_TEXT);
  let ciphertext;
  let checkCiphertext;

  try {
    const key = await deriveKey(passwordBytes, salt, ITERATIONS);
    ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      key,
      mnemonicBytes
    ));
    checkCiphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: chkIv, tagLength: 128 },
      key,
      checkBytes
    ));

    const envelope = {
      alg: ALGORITHM,
      iter: ITERATIONS,
      salt: base64urlEncode(salt),
      iv: base64urlEncode(iv),
      ct: base64urlEncode(ciphertext),
      chkIv: base64urlEncode(chkIv),
      chk: base64urlEncode(checkCiphertext)
    };
    envelope.fp = await computeFingerprint(envelope);

    return {
      payload: encodeEnvelope(envelope),
      fingerprint: envelope.fp
    };
  } finally {
    wipeBytes(passwordBytes);
    wipeBytes(mnemonicBytes);
    wipeBytes(checkBytes);
    wipeBytes(ciphertext);
    wipeBytes(checkCiphertext);
    wipeBytes(salt);
    wipeBytes(iv);
    wipeBytes(chkIv);
  }
}

async function decryptPayload(payload, password) {
  const envelope = decodeEnvelope(payload);
  const salt = base64urlDecode(envelope.salt);
  const iv = base64urlDecode(envelope.iv);
  const ciphertext = base64urlDecode(envelope.ct);
  const passwordBytes = new TextEncoder().encode(password);
  let plaintextBytes;

  try {
    await assertFingerprint(envelope);
    if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 17) {
      throw new Error("Wrong password or corrupted QR.");
    }

    const key = await deriveKey(passwordBytes, salt, envelope.iter);
    try {
      plaintextBytes = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv, tagLength: 128 }, key, ciphertext));
    } catch {
      throw new Error("Wrong password or corrupted QR.");
    }

    const mnemonic = new TextDecoder().decode(plaintextBytes);
    await validateMnemonic(mnemonic);
    return mnemonic;
  } finally {
    wipeBytes(passwordBytes);
    wipeBytes(plaintextBytes);
    wipeBytes(ciphertext);
    wipeBytes(salt);
    wipeBytes(iv);
  }
}

async function checkPayload(payload, password) {
  const envelope = decodeEnvelope(payload);

  const salt = base64urlDecode(envelope.salt);
  const chkIv = base64urlDecode(envelope.chkIv);
  const checkCiphertext = base64urlDecode(envelope.chk);
  const passwordBytes = new TextEncoder().encode(password);
  let checkPlaintext;

  try {
    await assertFingerprint(envelope);
    if (salt.length !== 16 || chkIv.length !== 12 || checkCiphertext.length < 17) {
      throw new Error("Wrong password or corrupted QR.");
    }

    const key = await deriveKey(passwordBytes, salt, envelope.iter);
    try {
      checkPlaintext = new Uint8Array(await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: chkIv, tagLength: 128 },
        key,
        checkCiphertext
      ));
    } catch {
      throw new Error("Wrong password or corrupted QR.");
    }

    if (new TextDecoder().decode(checkPlaintext) !== CHECK_TEXT) throw new Error("Wrong password or corrupted QR.");
    return envelope.fp;
  } finally {
    wipeBytes(passwordBytes);
    wipeBytes(checkPlaintext);
    wipeBytes(checkCiphertext);
    wipeBytes(salt);
    wipeBytes(chkIv);
  }
}

function getPasswordWarnings(password) {
  const warnings = [];
  if (password.length < 12) warnings.push("short password");
  if (BAD_PASSWORDS.has(password.trim().toLowerCase())) warnings.push("common password");
  return warnings;
}

function passwordWarningText(password) {
  const warnings = getPasswordWarnings(password);
  if (!warnings.length) return "";
  return `Warning: ${warnings.join(" and ")}. Anyone with the QR can try guesses offline.`;
}

function assertPasswordNotEmpty(password) {
  if (password.length === 0) throw new Error("Password cannot be empty.");
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

function clearField(input) {
  input.value = "";
  if (typeof input.setSelectionRange === "function") input.setSelectionRange(0, 0);
  if (input.type === "text" && (input.id.includes("password") || input.id === "confirm-password")) {
    input.type = "password";
  }
}

function clearScannerCanvas() {
  for (const canvas of document.querySelectorAll(".scanner canvas")) {
    const context = canvas.getContext("2d");
    context.clearRect(0, 0, canvas.width, canvas.height);
    canvas.width = 0;
    canvas.height = 0;
  }
}

function clearSensitiveOutputs() {
  clearField(elements.mnemonic);
  clearField(elements.encryptPassword);
  clearField(elements.confirmPassword);
  clearField(elements.recoverPassword);
  clearField(elements.checkPassword);
  clearField(elements.payloadInput);
  clearField(elements.checkPayloadInput);
  clearField(elements.payloadOutput);
  clearField(elements.fingerprintOutput);
  clearField(elements.recoveredMnemonic);
  clearField(elements.checkFingerprintOutput);
  elements.checkStatus.textContent = "No QR checked yet.";
  elements.qrOutput.className = "qr-frame qr-placeholder";
  elements.qrOutput.textContent = "QR appears here after encryption.";
  elements.printQr.textContent = "";
  elements.printFingerprint.textContent = "";
  elements.printButton.disabled = true;
  elements.copyPayloadButton.disabled = true;
  elements.copyMnemonicButton.disabled = true;
  setMessage(elements.encryptMessage, "");
  setMessage(elements.recoverMessage, "");
  setMessage(elements.checkMessage, "");
  for (const button of document.querySelectorAll("[data-toggle-password]")) {
    button.textContent = "Show";
  }
}

function clearSecrets(message = "Camera stopped. Paste works everywhere.") {
  stopScanner(message);
  clearScannerCanvas();
  clearSensitiveOutputs();
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
  if (name !== "recover") stopScanner("Camera stopped. Paste works everywhere.");
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

function togglePasswordVisibility(button) {
  const input = document.getElementById(button.dataset.togglePassword);
  if (!input) return;

  const visible = input.type === "text";
  input.type = visible ? "password" : "text";
  button.textContent = visible ? "Show" : "Hide";
  button.setAttribute("aria-label", `${visible ? "Show" : "Hide"} ${input.id.replace(/-/g, " ")}`);
}

function isCameraSupported() {
  return Boolean(navigator.mediaDevices && navigator.mediaDevices.getUserMedia && typeof qrDecoder === "function");
}

function getScanner(button) {
  const root = button.closest(".scanner");
  return {
    root,
    target: document.getElementById(button.dataset.scanTarget),
    startButton: button,
    stopButton: root.querySelector("[data-stop-scan]"),
    preview: root.querySelector(".scanner-preview"),
    video: root.querySelector("video"),
    canvas: root.querySelector("canvas"),
    message: root.querySelector("[data-scan-message]")
  };
}

async function requestCameraStream() {
  try {
    return await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: "environment" } },
      audio: false
    });
  } catch (error) {
    if (error && (error.name === "NotAllowedError" || error.name === "SecurityError")) throw error;
    return navigator.mediaDevices.getUserMedia({ video: true, audio: false });
  }
}

async function startScanner(button) {
  activeScanner = getScanner(button);
  if (!isCameraSupported()) {
    setMessage(activeScanner.message, "Camera scanning is unavailable. Paste the encrypted payload instead.", "error");
    activeScanner = null;
    return;
  }

  stopScanner();
  activeScanner = getScanner(button);
  setMessage(activeScanner.message, "Starting camera...");
  activeScanner.startButton.disabled = true;

  try {
    scannerStream = await requestCameraStream();
    activeScanner.video.srcObject = scannerStream;
    activeScanner.preview.hidden = false;
    activeScanner.stopButton.hidden = false;
    await activeScanner.video.play();
    activeScanner.startButton.disabled = false;
    setMessage(activeScanner.message, "Point the camera at a Memo QR code.");
    scanFrame();
  } catch {
    activeScanner.startButton.disabled = false;
    stopScanner("Camera unavailable. Paste the encrypted payload instead.", "error");
  }
}

function stopScanner(message, type = "") {
  if (scannerFrameId !== null) {
    cancelAnimationFrame(scannerFrameId);
    scannerFrameId = null;
  }

  if (scannerStream) {
    for (const track of scannerStream.getTracks()) track.stop();
    scannerStream = null;
  }

  scannerBusy = false;
  if (activeScanner) {
    activeScanner.video.pause();
    activeScanner.video.srcObject = null;
    activeScanner.preview.hidden = true;
    activeScanner.stopButton.hidden = true;
    activeScanner.startButton.disabled = !isCameraSupported();
  }
  clearScannerCanvas();
  if (message !== undefined && activeScanner) setMessage(activeScanner.message, message, type);
  activeScanner = null;
}

function scanFrame() {
  if (!scannerStream || !activeScanner) return;
  scannerFrameId = requestAnimationFrame(scanFrame);

  const video = activeScanner.video;
  if (scannerBusy || video.readyState < 2 || !video.videoWidth || !video.videoHeight) return;

  scannerBusy = true;
  const scale = Math.min(1, 720 / Math.max(video.videoWidth, video.videoHeight));
  const width = Math.max(1, Math.floor(video.videoWidth * scale));
  const height = Math.max(1, Math.floor(video.videoHeight * scale));
  const canvas = activeScanner.canvas;
  const context = canvas.getContext("2d", { willReadFrequently: true });

  canvas.width = width;
  canvas.height = height;
  context.drawImage(video, 0, 0, width, height);

  const imageData = context.getImageData(0, 0, width, height);
  const result = qrDecoder(imageData.data, width, height, { inversionAttempts: "dontInvert" });
  scannerBusy = false;

  if (result && result.data) handleScanResult(result.data);
}

function handleScanResult(rawValue) {
  const payload = rawValue.trim();
  if (!payload.startsWith(PREFIX)) {
    if (activeScanner) setMessage(activeScanner.message, "Not a Memo QR payload.");
    return;
  }

  if (activeScanner) activeScanner.target.value = payload;
  setMessage(elements.recoverMessage, "");
  setMessage(elements.checkMessage, "");
  stopScanner("QR payload scanned.", "success");
}

async function handleEncrypt(event) {
  event.preventDefault();
  setBusy(elements.encryptForm, true);
  setMessage(elements.encryptMessage, "Encrypting locally...");

  try {
    const mnemonic = normalizeMnemonic(elements.mnemonic.value);
    assertPasswordNotEmpty(elements.encryptPassword.value);
    if (elements.encryptPassword.value !== elements.confirmPassword.value) throw new Error("Passwords do not match.");
    await validateMnemonic(mnemonic);
    const { payload, fingerprint } = await encryptMnemonic(mnemonic, elements.encryptPassword.value);
    elements.payloadOutput.value = payload;
    elements.fingerprintOutput.value = `MNQR-FP: ${fingerprint}`;
    elements.printFingerprint.textContent = `Fingerprint: MNQR-FP: ${fingerprint}`;
    renderQR(payload);
    elements.printButton.disabled = false;
    elements.copyPayloadButton.disabled = false;
    const warning = passwordWarningText(elements.encryptPassword.value);
    setMessage(elements.encryptMessage, warning || "Encrypted QR payload generated.", warning ? "warning" : "success");
  } catch (error) {
    setMessage(elements.encryptMessage, error.message || "Invalid mnemonic.", "error");
  } finally {
    setBusy(elements.encryptForm, false);
  }
}

async function handleRecover(event) {
  event.preventDefault();
  stopScanner("Camera stopped. Paste works everywhere.");
  setBusy(elements.recoverForm, true);
  elements.recoveredMnemonic.value = "";
  elements.copyMnemonicButton.disabled = true;
  setMessage(elements.recoverMessage, "Decrypting locally...");

  try {
    const password = elements.recoverPassword.value;
    assertPasswordNotEmpty(password);
    const mnemonic = await decryptPayload(elements.payloadInput.value, password);
    elements.recoveredMnemonic.value = mnemonic;
    elements.copyMnemonicButton.disabled = false;
    setMessage(elements.recoverMessage, "Mnemonic recovered.", "success");
  } catch (error) {
    const safeMessage = error.message === "Invalid QR payload."
      ? error.message
      : "Wrong password or corrupted QR.";
    setMessage(elements.recoverMessage, safeMessage, "error");
  } finally {
    setBusy(elements.recoverForm, false);
  }
}

async function handleCheck(event) {
  event.preventDefault();
  stopScanner("Camera stopped. Paste works everywhere.");
  setBusy(elements.checkForm, true);
  elements.checkFingerprintOutput.value = "";
  elements.checkStatus.textContent = "Checking QR...";
  setMessage(elements.checkMessage, "Checking locally...");

  try {
    const password = elements.checkPassword.value;
    assertPasswordNotEmpty(password);
    const fingerprint = await checkPayload(elements.checkPayloadInput.value, password);
    elements.checkFingerprintOutput.value = `MNQR-FP: ${fingerprint}`;
    elements.checkStatus.textContent = "QR and password verified. The mnemonic was not displayed.";
    setMessage(elements.checkMessage, "QR and password verified.", "success");
  } catch (error) {
    const safeMessage = error.message === "Invalid QR payload."
      ? error.message
      : "Wrong password or corrupted QR.";
    elements.checkStatus.textContent = "No QR verified.";
    setMessage(elements.checkMessage, safeMessage, "error");
  } finally {
    setBusy(elements.checkForm, false);
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
  elements.checkForm.addEventListener("submit", handleCheck);
  elements.printButton.addEventListener("click", () => window.print());
  elements.copyPayloadButton.addEventListener("click", () => copyText(elements.payloadOutput.value, elements.encryptMessage));
  elements.copyMnemonicButton.addEventListener("click", () => copyText(elements.recoveredMnemonic.value, elements.recoverMessage));
  for (const button of document.querySelectorAll("[data-scan-target]")) {
    button.addEventListener("click", () => startScanner(button));
  }
  for (const button of document.querySelectorAll("[data-stop-scan]")) {
    button.addEventListener("click", () => stopScanner("Camera stopped. Paste works everywhere."));
  }
  window.addEventListener("beforeunload", () => clearSecrets());
  window.addEventListener("pagehide", () => clearSecrets());
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) clearSecrets();
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopScanner("Camera stopped. Paste works everywhere.");
  });

  if (!isCameraSupported()) {
    for (const button of document.querySelectorAll("[data-scan-target]")) {
      button.disabled = true;
      setMessage(button.closest(".scanner").querySelector("[data-scan-message]"), "Camera scanning is unavailable. Paste the encrypted payload instead.");
    }
  }

  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => switchTab(tab.dataset.tab));
  }
  for (const button of document.querySelectorAll("[data-clear]")) {
    button.addEventListener("click", clearSecrets);
  }
  for (const button of document.querySelectorAll("[data-toggle-password]")) {
    button.addEventListener("click", () => togglePasswordVisibility(button));
  }
}

init();
