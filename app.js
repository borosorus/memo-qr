"use strict";

const PREFIX = "MNQR1.";
const ALGORITHM = "PBKDF2-SHA256-AES256GCM";
const ITERATIONS = 600000;
const CHECK_TEXT = "MNQR-CHECK";
const MAX_TEXT_BYTES = 2048;
const BAD_PASSWORDS = new Set(["password", "123456", "bitcoin", "wallet", "secret"]);

const $ = (selector) => document.querySelector(selector);
const qrDecoder = window.jsQR;

const elements = {
  supportError: $("#support-error"),
  encryptForm: $("#encrypt-form"),
  recoverForm: $("#recover-form"),
  checkForm: $("#check-form"),
  plainText: $("#plain-text"),
  encryptPassword: $("#encrypt-password"),
  confirmPassword: $("#confirm-password"),
  recoverPassword: $("#recover-password"),
  checkPassword: $("#check-password"),
  payloadOutput: $("#payload-output"),
  fingerprintOutput: $("#fingerprint-output"),
  payloadInput: $("#payload-input"),
  checkPayloadInput: $("#check-payload-input"),
  recoveredText: $("#recovered-text"),
  encryptMessage: $("#encrypt-message"),
  recoverMessage: $("#recover-message"),
  checkMessage: $("#check-message"),
  encryptResult: $("#encrypt-result"),
  encryptResultTitle: $("#encrypt-result-title"),
  encryptResultDetail: $("#encrypt-result-detail"),
  recoverResult: $("#recover-result"),
  recoverResultTitle: $("#recover-result-title"),
  recoverResultDetail: $("#recover-result-detail"),
  checkResult: $("#check-result"),
  checkStatus: $("#check-status"),
  checkDetail: $("#check-detail"),
  checkResultMessage: $("#check-result-message"),
  checkResultTitle: $("#check-result-title"),
  checkResultDetail: $("#check-result-detail"),
  checkFingerprintOutput: $("#check-fingerprint-output"),
  qrOutput: $("#qr-output"),
  printQr: $("#print-qr"),
  printFingerprint: $("#print-fingerprint"),
  printButton: $("#print-button"),
  exportPngButton: $("#export-png-button"),
  copyPayloadButton: $("#copy-payload-button"),
  copyTextButton: $("#copy-text-button")
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

function bytesToHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function textBytes(text) {
  return new TextEncoder().encode(text);
}

function validatePlainText(text) {
  if (typeof text !== "string" || text.trim().length === 0) {
    throw new Error("Text cannot be empty.");
  }
  const bytes = textBytes(text);
  try {
    if (bytes.length > MAX_TEXT_BYTES) throw new Error(`Text is too large. Max ${MAX_TEXT_BYTES} UTF-8 bytes.`);
  } finally {
    wipeBytes(bytes);
  }
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

async function encryptText(plainText, password) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const chkIv = randomBytes(12);
  const encoder = new TextEncoder();
  const passwordBytes = encoder.encode(password);
  const plainTextBytes = encoder.encode(plainText);
  const checkBytes = encoder.encode(CHECK_TEXT);
  let ciphertext;
  let checkCiphertext;

  try {
    const key = await deriveKey(passwordBytes, salt, ITERATIONS);
    ciphertext = new Uint8Array(await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      key,
      plainTextBytes
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
    wipeBytes(plainTextBytes);
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

    const plainText = new TextDecoder().decode(plaintextBytes);
    try {
      validatePlainText(plainText);
    } catch {
      throw new Error("Wrong password or corrupted QR.");
    }
    return plainText;
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
  if (!node) return;
  node.textContent = text;
  node.className = `message ${type}`.trim();
}

function setResultStatus(card, titleNode, detailNode, state, title, detail) {
  card.className = `result-status ${state}`.trim();
  titleNode.textContent = title;
  detailNode.textContent = detail;
}

function setCheckState(state, detail = "") {
  elements.checkResult.className = `check-result ${state}`.trim();
  elements.checkStatus.textContent = {
    idle: "No QR checked yet.",
    progress: "Checking QR...",
    success: "Fingerprint verified.",
    error: "Fingerprint not verified."
  }[state] || "No QR checked yet.";
  elements.checkDetail.textContent = detail;
}

function setEncryptState(state, title, detail) {
  setResultStatus(elements.encryptResult, elements.encryptResultTitle, elements.encryptResultDetail, state, title, detail);
}

function setRecoverState(state, title, detail) {
  setResultStatus(elements.recoverResult, elements.recoverResultTitle, elements.recoverResultDetail, state, title, detail);
}

function setCheckMessageState(state, title, detail) {
  setResultStatus(elements.checkResultMessage, elements.checkResultTitle, elements.checkResultDetail, state, title, detail);
}

function setScannerState(scanner, state, title, detail) {
  if (!scanner || !scanner.target) return;
  if (scanner.target === elements.payloadInput) {
    setRecoverState(state, title, detail);
    return;
  }
  if (scanner.target === elements.checkPayloadInput) {
    setCheckMessageState(state, title, detail);
  }
}

function renderQR(text) {
  const qr = qrcode(0, "M");
  qr.addData(text);
  qr.make();
  const svg = qr.createSvgTag(5, 2, "Encrypted payload QR", "Encrypted payload QR");
  elements.qrOutput.classList.remove("qr-placeholder");
  elements.qrOutput.innerHTML = svg;
  elements.printQr.innerHTML = svg;
}

function currentQrSvg() {
  return elements.qrOutput.querySelector("svg");
}

function svgToPngDataUrl(svg) {
  return new Promise((resolve, reject) => {
    const markup = new XMLSerializer().serializeToString(svg);
    const blob = new Blob([markup], { type: "image/svg+xml;charset=utf-8" });
    const objectUrl = URL.createObjectURL(blob);
    const image = new Image();

    image.onload = () => {
      const width = image.naturalWidth || 1024;
      const height = image.naturalHeight || width;
      const canvas = document.createElement("canvas");
      const context = canvas.getContext("2d");

      canvas.width = width;
      canvas.height = height;
      context.fillStyle = "#ffffff";
      context.fillRect(0, 0, width, height);
      context.drawImage(image, 0, 0, width, height);

      URL.revokeObjectURL(objectUrl);
      resolve(canvas.toDataURL("image/png"));
    };

    image.onerror = () => {
      URL.revokeObjectURL(objectUrl);
      reject(new Error("PNG export failed."));
    };

    image.src = objectUrl;
  });
}

async function exportQrPng() {
  const svg = currentQrSvg();
  if (!svg) {
    setMessage(elements.encryptMessage, "Generate a QR before exporting PNG.", "error");
    setEncryptState("error", "PNG export failed.", "Generate a QR before exporting PNG.");
    return;
  }

  elements.exportPngButton.disabled = true;
  setMessage(elements.encryptMessage, "Preparing PNG...");
  setEncryptState("progress", "Preparing PNG...", "Rendering the current QR to a local PNG file.");

  try {
    const dataUrl = await svgToPngDataUrl(svg);
    const link = document.createElement("a");
    link.href = dataUrl;
    link.download = "mnqr1-qr.png";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setMessage(elements.encryptMessage, "PNG exported.", "success");
    setEncryptState("success", "QR ready.", "Encrypted QR, fingerprint, and PNG export are ready.");
  } catch (error) {
    setMessage(elements.encryptMessage, error.message || "PNG export failed.", "error");
    setEncryptState("error", "PNG export failed.", error.message || "PNG export failed.");
  } finally {
    elements.exportPngButton.disabled = false;
  }
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
  clearField(elements.plainText);
  clearField(elements.encryptPassword);
  clearField(elements.confirmPassword);
  clearField(elements.recoverPassword);
  clearField(elements.checkPassword);
  clearField(elements.payloadInput);
  clearField(elements.checkPayloadInput);
  clearField(elements.payloadOutput);
  clearField(elements.fingerprintOutput);
  clearField(elements.recoveredText);
  clearField(elements.checkFingerprintOutput);
  setEncryptState("idle", "No QR generated yet.", "Encrypt text to generate the QR payload and fingerprint.");
  setRecoverState("idle", "No text recovered yet.", "Load a QR payload and enter its password to reveal the text locally.");
  setCheckState("idle", "If the QR and password match, this shows the payload fingerprint without revealing the text.");
  setCheckMessageState("idle", "No verification result yet.", "Check mode verifies the payload and password without decrypting the text into view.");
  elements.qrOutput.className = "qr-frame qr-placeholder";
  elements.qrOutput.textContent = "QR appears here after encryption.";
  elements.printQr.textContent = "";
  elements.printFingerprint.textContent = "";
  elements.printButton.disabled = true;
  elements.exportPngButton.disabled = true;
  elements.copyPayloadButton.disabled = true;
  elements.copyTextButton.disabled = true;
  setMessage(elements.encryptMessage, "");
  setMessage(elements.recoverMessage, "");
  setMessage(elements.checkMessage, "");
  for (const input of document.querySelectorAll("[data-import-file]")) input.value = "";
  for (const button of document.querySelectorAll("[data-toggle-password]")) {
    button.textContent = "Show";
  }
}

function clearSecrets(message = "Camera stopped. Image import and paste work everywhere.") {
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
  stopScanner("Camera stopped. Image import and paste work everywhere.");
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

function getScanner(node) {
  const root = node.closest(".scanner");
  return {
    root,
    target: document.getElementById(node.dataset.scanTarget || root.dataset.payloadTarget),
    startButton: root.querySelector("[data-scan-target]"),
    stopButton: root.querySelector("[data-stop-scan]"),
    preview: root.querySelector(".scanner-preview"),
    video: root.querySelector("video"),
    canvas: root.querySelector("canvas"),
    message: root.querySelector("[data-scan-message]")
  };
}

function getSourceDimensions(source) {
  return {
    width: source.naturalWidth || source.videoWidth || source.width || 0,
    height: source.naturalHeight || source.videoHeight || source.height || 0
  };
}

function decodeQrFromSource(source, canvas, maxDimension = 1440) {
  const { width: sourceWidth, height: sourceHeight } = getSourceDimensions(source);
  if (!sourceWidth || !sourceHeight) throw new Error("Could not read image.");

  const scale = Math.min(1, maxDimension / Math.max(sourceWidth, sourceHeight));
  const width = Math.max(1, Math.floor(sourceWidth * scale));
  const height = Math.max(1, Math.floor(sourceHeight * scale));
  const context = canvas.getContext("2d", { willReadFrequently: true });

  canvas.width = width;
  canvas.height = height;
  context.drawImage(source, 0, 0, width, height);

  const imageData = context.getImageData(0, 0, width, height);
  return qrDecoder(imageData.data, width, height, { inversionAttempts: "dontInvert" });
}

function loadImageElement(objectUrl) {
  return new Promise((resolve, reject) => {
    const image = new Image();
    image.decoding = "async";
    image.onload = () => resolve(image);
    image.onerror = () => reject(new Error("Could not read image."));
    image.src = objectUrl;
  });
}

async function decodeQrFromFile(file, canvas) {
  if (!file || (file.type && !file.type.startsWith("image/"))) throw new Error("Choose an image file.");
  if (typeof URL === "undefined" || typeof URL.createObjectURL !== "function") {
    throw new Error("Image import is unavailable in this browser.");
  }

  const objectUrl = URL.createObjectURL(file);
  let source;
  try {
    if (typeof createImageBitmap === "function") {
      try {
        source = await createImageBitmap(file);
      } catch {
        source = await loadImageElement(objectUrl);
      }
    } else {
      source = await loadImageElement(objectUrl);
    }
    return decodeQrFromSource(source, canvas);
  } finally {
    if (source && typeof source.close === "function") source.close();
    URL.revokeObjectURL(objectUrl);
  }
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
    setMessage(activeScanner.message, "Camera scanning is unavailable. Import an image or paste the encrypted payload instead.", "error");
    setScannerState(activeScanner, "error", "Camera unavailable.", "Import an image or paste the encrypted payload instead.");
    activeScanner = null;
    return;
  }

  stopScanner();
  activeScanner = getScanner(button);
  setMessage(activeScanner.message, "Starting camera...");
  setScannerState(activeScanner, "progress", "Starting camera...", "Point the camera at the QR code once the preview appears.");
  activeScanner.startButton.disabled = true;

  try {
    scannerStream = await requestCameraStream();
    activeScanner.video.srcObject = scannerStream;
    activeScanner.preview.hidden = false;
    activeScanner.stopButton.hidden = false;
    await activeScanner.video.play();
    activeScanner.startButton.disabled = false;
    setMessage(activeScanner.message, "Point the camera at a Memo QR code.");
    setScannerState(activeScanner, "progress", "Camera ready.", "Point the camera at a Memo QR code.");
    scanFrame();
  } catch {
    activeScanner.startButton.disabled = false;
    setScannerState(activeScanner, "error", "Camera unavailable.", "Import an image or paste the encrypted payload instead.");
    stopScanner("Camera unavailable. Import an image or paste the encrypted payload instead.", "error");
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
  let result;
  try {
    result = decodeQrFromSource(video, activeScanner.canvas, 720);
  } finally {
    scannerBusy = false;
  }

  if (result && result.data) handleScanResult(result.data, activeScanner, "QR payload scanned.");
}

function handleScanResult(rawValue, scanner = activeScanner, successMessage = "QR payload scanned.") {
  const payload = rawValue.trim();
  if (!payload.startsWith(PREFIX)) {
    if (scanner) setMessage(scanner.message, "Not a Memo QR payload.", "error");
    setScannerState(scanner, "error", "Scan failed.", "The scanned code is not a Memo QR payload.");
    return;
  }

  if (scanner) scanner.target.value = payload;
  setMessage(elements.recoverMessage, "");
  setMessage(elements.checkMessage, "");
  setScannerState(scanner, "success", "QR loaded.", "The payload was read successfully and is ready for the next step.");
  if (scanner && scanner === activeScanner) {
    stopScanner(successMessage, "success");
    return;
  }
  if (scanner) setMessage(scanner.message, successMessage, "success");
}

async function handleImageImport(input) {
  const scanner = getScanner(input);
  const file = input.files && input.files[0];
  if (!file) return;

  stopScanner();
  input.disabled = true;
  setMessage(scanner.message, "Reading image...");
  setScannerState(scanner, "progress", "Reading image...", "Decoding the selected image locally for a Memo QR payload.");

  try {
    const result = await decodeQrFromFile(file, scanner.canvas);
    if (!result || !result.data) throw new Error("No QR code found in image.");
    handleScanResult(result.data, scanner, "QR payload loaded from image.");
  } catch (error) {
    setMessage(scanner.message, error.message || "Could not read image.", "error");
    setScannerState(scanner, "error", "Image import failed.", error.message || "Could not read image.");
  } finally {
    input.value = "";
    input.disabled = false;
    clearScannerCanvas();
  }
}

async function handleEncrypt(event) {
  event.preventDefault();
  setBusy(elements.encryptForm, true);
  setMessage(elements.encryptMessage, "Encrypting locally...");
  setEncryptState("progress", "Generating QR...", "Deriving the encryption key and building the payload locally.");

  try {
    const plainText = elements.plainText.value;
    assertPasswordNotEmpty(elements.encryptPassword.value);
    if (elements.encryptPassword.value !== elements.confirmPassword.value) throw new Error("Passwords do not match.");
    validatePlainText(plainText);
    const { payload, fingerprint } = await encryptText(plainText, elements.encryptPassword.value);
    elements.payloadOutput.value = payload;
    elements.fingerprintOutput.value = `MNQR-FP: ${fingerprint}`;
    elements.printFingerprint.textContent = `Fingerprint: MNQR-FP: ${fingerprint}`;
    renderQR(payload);
    elements.printButton.disabled = false;
    elements.exportPngButton.disabled = false;
    elements.copyPayloadButton.disabled = false;
    const warning = passwordWarningText(elements.encryptPassword.value);
    setMessage(elements.encryptMessage, warning || "Encrypted QR payload generated.", warning ? "warning" : "success");
    setEncryptState(
      warning ? "warning" : "success",
      "QR generated.",
      warning || "Encrypted QR payload and fingerprint are ready."
    );
  } catch (error) {
    setMessage(elements.encryptMessage, error.message || "Invalid text.", "error");
    setEncryptState("error", "Generation failed.", error.message || "Invalid text.");
  } finally {
    setBusy(elements.encryptForm, false);
  }
}

async function handleRecover(event) {
  event.preventDefault();
  stopScanner("Camera stopped. Image import and paste work everywhere.");
  setBusy(elements.recoverForm, true);
  elements.recoveredText.value = "";
  elements.copyTextButton.disabled = true;
  setMessage(elements.recoverMessage, "Decrypting locally...");
  setRecoverState("progress", "Recovering text...", "Decrypting the QR payload locally with the provided password.");

  try {
    const password = elements.recoverPassword.value;
    assertPasswordNotEmpty(password);
    const plainText = await decryptPayload(elements.payloadInput.value, password);
    elements.recoveredText.value = plainText;
    elements.copyTextButton.disabled = false;
    setMessage(elements.recoverMessage, "Text recovered.", "success");
    setRecoverState("success", "Text recovered.", "The payload and password matched, and the text is now visible on this page.");
  } catch (error) {
    const safeMessage = error.message === "Invalid QR payload."
      ? error.message
      : "Wrong password or corrupted QR.";
    setMessage(elements.recoverMessage, safeMessage, "error");
    setRecoverState("error", "Recovery failed.", safeMessage);
  } finally {
    setBusy(elements.recoverForm, false);
  }
}

async function handleCheck(event) {
  event.preventDefault();
  stopScanner("Camera stopped. Image import and paste work everywhere.");
  setBusy(elements.checkForm, true);
  elements.checkFingerprintOutput.value = "";
  setCheckState("progress", "Verifying the encrypted check value locally. The text stays hidden.");
  setMessage(elements.checkMessage, "Checking locally...");
  setCheckMessageState("progress", "Checking QR...", "Verifying the payload and password locally without revealing the text.");

  try {
    const password = elements.checkPassword.value;
    assertPasswordNotEmpty(password);
    const fingerprint = await checkPayload(elements.checkPayloadInput.value, password);
    elements.checkFingerprintOutput.value = `MNQR-FP: ${fingerprint}`;
    setCheckState("success", "The QR payload and password match. This fingerprint identifies that encrypted payload only; it does not reveal the text.");
    setMessage(elements.checkMessage, "QR and password verified.", "success");
    setCheckMessageState("success", "QR verified.", "The encrypted payload fingerprint was recovered successfully.");
  } catch (error) {
    const safeMessage = error.message === "Invalid QR payload."
      ? error.message
      : "Wrong password or corrupted QR.";
    setCheckState("error", "The QR could not be validated. This usually means the password is wrong, the image does not contain this QR payload, or the payload is corrupted.");
    setMessage(elements.checkMessage, safeMessage, "error");
    setCheckMessageState("error", "Verification failed.", safeMessage);
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

  if (typeof qrcode !== "function") {
    elements.supportError.textContent = "Required local assets failed to load.";
    elements.supportError.classList.remove("hidden");
    for (const control of document.querySelectorAll("button, input, textarea")) control.disabled = true;
    return;
  }

  elements.encryptForm.addEventListener("submit", handleEncrypt);
  elements.recoverForm.addEventListener("submit", handleRecover);
  elements.checkForm.addEventListener("submit", handleCheck);
  elements.printButton.addEventListener("click", () => window.print());
  elements.exportPngButton.addEventListener("click", exportQrPng);
  elements.copyPayloadButton.addEventListener("click", () => copyText(elements.payloadOutput.value, elements.encryptMessage));
  elements.copyTextButton.addEventListener("click", () => copyText(elements.recoveredText.value, elements.recoverMessage));
  for (const button of document.querySelectorAll("[data-scan-target]")) {
    button.addEventListener("click", () => startScanner(button));
  }
  for (const button of document.querySelectorAll("[data-stop-scan]")) {
    button.addEventListener("click", () => stopScanner("Camera stopped. Image import and paste work everywhere."));
  }
  for (const input of document.querySelectorAll("[data-import-file]")) {
    input.addEventListener("change", () => handleImageImport(input));
  }
  window.addEventListener("beforeunload", () => clearSecrets());
  window.addEventListener("pagehide", () => clearSecrets());
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) clearSecrets();
  });
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) stopScanner("Camera stopped. Image import and paste work everywhere.");
  });

  if (!isCameraSupported()) {
    for (const button of document.querySelectorAll("[data-scan-target]")) {
      button.disabled = true;
      setMessage(button.closest(".scanner").querySelector("[data-scan-message]"), "Camera scanning is unavailable. Import an image or paste the encrypted payload instead.");
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
