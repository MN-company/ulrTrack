/**
 * ulrTrack V21 Metrics & Security
 * Obfuscated logic for Adblock Detection and Deep Fingerprinting.
 */

// --- Adblock Detection (V3/Firefox Compatible) ---
async function checkAdBlock() {
    let blocked = false;

    // 1. CSS Check (Element Hiding)
    var bait = document.getElementById('ads-bait');
    if (!bait || bait.offsetParent === null || bait.offsetHeight === 0 || bait.style.display === 'none') {
        blocked = true;
    }

    // 2. Network Check (Canary Request)
    try {
        await fetch('/pagead/ads.js', { method: 'HEAD', mode: 'no-cors' });
    } catch (e) {
        blocked = true;
    }

    return blocked;
}

// --- Deep Fingerprinting ---
function getCanvasHash() {
    try {
        var canvas = document.createElement('canvas');
        var ctx = canvas.getContext('2d');
        ctx.textBaseline = "top"; ctx.font = "14px 'Arial'"; ctx.textBaseline = "alphabetic";
        ctx.fillStyle = "#f60"; ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = "#069"; ctx.fillText("ulrTrack_V16_FP", 2, 15);
        ctx.fillStyle = "rgba(102, 204, 0, 0.7)"; ctx.fillText("ulrTrack_V16_FP", 4, 17);
        var b64 = canvas.toDataURL().replace("data:image/png;base64,", "");
        var bin = atob(b64);
        var crc = -1;
        for (var i = 0; i < bin.length; i++) { crc = crc >>> 8 ^ "0123456789".charCodeAt(crc & 255) ^ bin.charCodeAt(i); }
        return (crc >>> 0).toString(16);
    } catch (e) { return null; }
}

function getWebGLRenderer() {
    try {
        var c = document.createElement('canvas');
        var gl = c.getContext('webgl') || c.getContext('experimental-webgl');
        var i = gl.getExtension('WEBGL_debug_renderer_info');
        return gl.getParameter(i.UNMASKED_RENDERER_WEBGL);
    } catch (e) { return "Unknown"; }
}

// --- Telemetry Sender ---
async function sendMetrics(visitId, destination, callback) {
    // 1. Collect Data
    var userLang = navigator.language || navigator.userLanguage || "Unknown";
    var isBlocked = await checkAdBlock();
    var fpCanvas = getCanvasHash();
    var fpWebgl = getWebGLRenderer();

    // 2. Prepare Payload
    var data = JSON.stringify({
        visit_id: visitId,
        screen: window.screen.width + "x" + window.screen.height,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        webdriver: navigator.webdriver,
        language: userLang,
        adblock: isBlocked,
        canvas_hash: fpCanvas,
        webgl_renderer: fpWebgl
    });

    // 3. Send
    if (navigator.sendBeacon) {
        navigator.sendBeacon("/api/beacon", data);
    } else {
        // Fallback for very old browsers (unlikely)
        var xhr = new XMLHttpRequest();
        xhr.open("POST", "/api/beacon", true);
        xhr.setRequestHeader("Content-Type", "application/json");
        xhr.send(data);
    }

    // 4. Callback (Redirect)
    if (callback && destination) {
        setTimeout(function () {
            window.location.replace(destination);
        }, 300);
    }
}
