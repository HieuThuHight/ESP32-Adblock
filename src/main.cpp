// ESP AdBlock — DNS sinkhole + web dashboard for the ESP32.
// Blocklist = sorted 40-bit FNV-1a hashes in flash, binary-searched.
// Dashboard at http://espadblock.local : per-client stats, system info,
// ban clients, add custom block domains. All control state persisted to flash.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <LittleFS.h>
#include <ESPmDNS.h>
#include <WebServer.h>
#include <Update.h>            // firmware OTA
#include <HTTPClient.h>        // remote blocklist fetch
#include <WiFiClientSecure.h>  // https fetch
#include <ArduinoOTA.h>        // network firmware flashing (pio run over wifi)
#include <DNSServer.h>         // captive-portal catch-all DNS
#include <Preferences.h>       // NVS store for provisioned WiFi creds
#include "lwip/etharp.h"
#include "lwip/netif.h"
#include "secrets.h"   // WIFI_SSID / WIFI_PASS — used only as a FALLBACK if no creds
                       // have been provisioned via the captive portal (copy secrets.example.h)

// ---- config ----
static const IPAddress UPSTREAM(9, 9, 9, 9);     // Quad9
static const uint16_t DNS_PORT = 53;
static const char* BLOCKLIST_PATH = "/blocklist.bin";
static const int HASH_BYTES = 5;
static const uint64_t HASH_MASK = (1ULL << (HASH_BYTES * 8)) - 1;

// ---- globals ----
WiFiUDP dnsServer, upstreamCli;
WebServer web(80);
File blocklist;
uint32_t numHashes = 0, totalBlocked = 0, totalAllowed = 0;
uint8_t* psramCache = nullptr;
uint8_t buf[600];

struct Dev { uint32_t ip; uint8_t mac[6]; uint32_t blocked, allowed, lastSeen; bool banned; String label; };
static const int MAX_CLIENTS = 96;
Dev clients[MAX_CLIENTS]; int numClients = 0;

static const int MAX_CUSTOM = 200;
String customDom[MAX_CUSTOM]; uint64_t customHash[MAX_CUSTOM]; int numCustom = 0;

static const int MAX_BAN = 32;
uint32_t bannedIP[MAX_BAN]; int numBanned = 0;

// remote blocklist auto-update
String updateUrl = "https://github.com/HieuThuHight/ESP32-Adblock/releases/download/latest/blocklist.bin";              // URL of a prebuilt blocklist.bin (e.g. GitHub release asset)
uint32_t updateIntervalH = 72;      // hours between auto-fetches (72 = 3 days)
uint32_t lastCheckMs = 0;
String updateStatus = "never";

// WiFi provisioning (captive portal)
Preferences prefs;
DNSServer   dnsPortal;
String      portalOpts;             // <option> list of scanned networks, built once at portal start

// ---------- hashing / matching ----------
static uint64_t fnv40(const char* s, size_t n) {
  uint64_t h = 0xcbf29ce484222325ULL;
  for (size_t i = 0; i < n; i++) { h ^= (uint8_t)s[i]; h *= 0x100000001b3ULL; }
  return h & HASH_MASK;
}
static bool inFlash(uint64_t h) {
  int32_t lo = 0, hi = (int32_t)numHashes - 1; uint8_t b[HASH_BYTES];
  while (lo <= hi) {
    int32_t mid = (lo + hi) >> 1;
    uint64_t v = 0;
    if (psramCache) {
      uint8_t* p = psramCache + (uint32_t)mid * HASH_BYTES;
      for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)p[k] << (8 * k);
    } else {
      blocklist.seek((uint32_t)mid * HASH_BYTES); blocklist.read(b, HASH_BYTES);
      for (int k = 0; k < HASH_BYTES; k++) v |= (uint64_t)b[k] << (8 * k);
    }
    if (v < h) lo = mid + 1; else if (v > h) hi = mid - 1; else return true;
  }
  return false;
}
static bool inCustom(uint64_t h) { for (int i = 0; i < numCustom; i++) if (customHash[i] == h) return true; return false; }
static bool isBlocked(const char* domain) {
  const char* p = domain;
  while (p && *p) {
    uint64_t h = fnv40(p, strlen(p));
    if (inFlash(h) || inCustom(h)) return true;
    const char* dot = strchr(p, '.'); if (!dot) break;
    const char* next = dot + 1; if (!strchr(next, '.')) break; p = next;
  }
  return false;
}

// ---------- persistence ----------
static void loadCustom() {
  numCustom = 0; File f = LittleFS.open("/custom.txt", "r"); if (!f) return;
  while (f.available() && numCustom < MAX_CUSTOM) {
    String l = f.readStringUntil('\n'); l.trim(); l.toLowerCase();
    if (l.length() && l.indexOf('.') > 0) { customDom[numCustom] = l; customHash[numCustom] = fnv40(l.c_str(), l.length()); numCustom++; }
  }
  f.close();
}
static void saveCustom() { File f = LittleFS.open("/custom.txt", "w"); if (!f) return; for (int i = 0; i < numCustom; i++) f.println(customDom[i]); f.close(); }
static bool addCustom(String d) {
  d.trim(); d.toLowerCase(); if (d.startsWith("www.")) d = d.substring(4);
  if (!d.length() || d.indexOf('.') < 0 || numCustom >= MAX_CUSTOM) return false;
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) return false;
  customDom[numCustom] = d; customHash[numCustom] = fnv40(d.c_str(), d.length()); numCustom++; saveCustom(); return true;
}
static void removeCustom(String d) {
  d.toLowerCase();
  for (int i = 0; i < numCustom; i++) if (customDom[i] == d) {
    for (int j = i; j < numCustom - 1; j++) { customDom[j] = customDom[j+1]; customHash[j] = customHash[j+1]; }
    numCustom--; saveCustom(); return;
  }
}
static bool isBannedIP(uint32_t ip) { for (int i = 0; i < numBanned; i++) if (bannedIP[i] == ip) return true; return false; }
static void loadBanned() {
  numBanned = 0; File f = LittleFS.open("/banned.txt", "r"); if (!f) return;
  while (f.available() && numBanned < MAX_BAN) { String l = f.readStringUntil('\n'); l.trim(); IPAddress ip; if (l.length() && ip.fromString(l)) bannedIP[numBanned++] = (uint32_t)ip; }
  f.close();
}
static void saveBanned() {
  numBanned = 0;
  for (int i = 0; i < numClients && numBanned < MAX_BAN; i++) if (clients[i].banned) bannedIP[numBanned++] = clients[i].ip;
  File f = LittleFS.open("/banned.txt", "w"); if (!f) return;
  for (int i = 0; i < numBanned; i++) { IPAddress ip(bannedIP[i]); f.println(ip.toString()); }
  f.close();
}

// ---------- client table ----------
static void getMac(uint32_t ip, uint8_t* mac) {
  memset(mac, 0, 6); ip4_addr_t ipa; ipa.addr = ip;
  struct eth_addr* eth = nullptr; const ip4_addr_t* ipret = nullptr;
  for (struct netif* nif = netif_list; nif; nif = nif->next)
    if (etharp_find_addr(nif, &ipa, &eth, &ipret) >= 0 && eth) { memcpy(mac, eth->addr, 6); return; }
}
static Dev* getClient(uint32_t ip) {
  for (int i = 0; i < numClients; i++) if (clients[i].ip == ip) { clients[i].lastSeen = millis(); return &clients[i]; }
  if (numClients < MAX_CLIENTS) {
    Dev* c = &clients[numClients++];
    c->ip = ip; c->blocked = c->allowed = 0; c->lastSeen = millis(); c->banned = isBannedIP(ip); c->label = "";
    getMac(ip, c->mac); return c;
  }
  return nullptr;
}

// ---------- DNS ----------
static size_t parseQuery(const uint8_t* pkt, int len, char* out, uint16_t* qtype, int* qend) {
  if (len < 13) return 0; int i = 12; size_t o = 0;
  while (i < len) { uint8_t l = pkt[i++]; if (l == 0) break; if (l & 0xC0) return 0;
    if (o + l + 1 >= 250 || i + l > len) return 0; if (o) out[o++] = '.';
    for (uint8_t k = 0; k < l; k++) out[o++] = tolower(pkt[i++]); }
  out[o] = 0; if (i + 4 > len) return 0; *qtype = (pkt[i] << 8) | pkt[i + 1]; *qend = i + 4;
  if (o > 4 && strncmp(out, "www.", 4) == 0) { memmove(out, out + 4, o - 3); o -= 4; }
  return o;
}
static int buildBlocked(int qend, uint16_t qtype) {
  buf[2] = 0x81; buf[3] = 0x80; buf[6] = 0; buf[7] = (qtype == 1) ? 1 : 0; buf[8] = 0; buf[9] = 0; buf[10] = 0; buf[11] = 0;
  if (qtype != 1) return qend;
  const uint8_t ans[] = {0xC0,0x0C, 0,1, 0,1, 0,0,1,0x2C, 0,4, 0,0,0,0};
  memcpy(buf + qend, ans, sizeof(ans)); return qend + sizeof(ans);
}
static int forwardUpstream(int qlen) {
  upstreamCli.beginPacket(UPSTREAM, 53); upstreamCli.write(buf, qlen); upstreamCli.endPacket();
  uint32_t t0 = millis();
  while (millis() - t0 < 1000) { int sz = upstreamCli.parsePacket(); if (sz > 0) return upstreamCli.read(buf, sizeof(buf)); delay(1); }
  return 0;
}
// Drain a whole RX burst per call (capped, so web/OTA still get a turn) instead of
// one packet per loop iteration. Returns true if any query was handled this call.
static bool handleDns() {
  bool did = false;
  for (int budget = 0; budget < 16; budget++) {
    int sz = dnsServer.parsePacket(); if (sz <= 0) break;
    did = true;
    IPAddress cip = dnsServer.remoteIP(); uint16_t cport = dnsServer.remotePort();
    int qlen = dnsServer.read(buf, sizeof(buf)); if (qlen < 13) continue;
    char domain[256]; uint16_t qtype = 0; int qend = qlen;
    size_t dl = parseQuery(buf, qlen, domain, &qtype, &qend);
    Dev* c = getClient((uint32_t)cip);
    bool ban = c && c->banned;
    bool blocked = ban || (dl && numHashes && isBlocked(domain));
    int rlen;
    if (blocked) { rlen = buildBlocked(qend, qtype); totalBlocked++; if (c) c->blocked++; }
    else         { rlen = forwardUpstream(qlen);     totalAllowed++; if (c) c->allowed++; }
    if (rlen > 0) { dnsServer.beginPacket(cip, cport); dnsServer.write(buf, rlen); dnsServer.endPacket(); }
  }
  return did;
}

// ---------- web ----------
static String macStr(const uint8_t* m) { char s[18]; snprintf(s, sizeof(s), "%02x:%02x:%02x:%02x:%02x:%02x", m[0],m[1],m[2],m[3],m[4],m[5]); return String(s); }
static String jesc(const String& s) { String o; for (char ch : s) { if (ch == '"' || ch == '\\') o += '\\'; o += ch; } return o; }

#include "page.h"   // dashboard HTML (PROGMEM) — see issue #6

static void handleStats() {
  uint32_t up = millis() / 1000;
  char ut[24]; snprintf(ut, sizeof(ut), "%lud %luh %lum", up/86400, (up%86400)/3600, (up%3600)/60);
  String j = "{\"ip\":\"" + WiFi.localIP().toString() + "\",\"blocked\":" + totalBlocked + ",\"allowed\":" + totalAllowed +
             ",\"domains\":" + numHashes + ",\"rssi\":" + WiFi.RSSI() + ",\"temp\":" + String(temperatureRead(), 1) +
             ",\"heap\":" + ESP.getFreeHeap() + ",\"uptime\":\"" + ut + "\"" +
             ",\"upurl\":\"" + jesc(updateUrl) + "\",\"upiv\":" + updateIntervalH + ",\"upstat\":\"" + jesc(updateStatus) + "\"" +
             ",\"clients\":[";
  for (int i = 0; i < numClients; i++) { Dev& c = clients[i]; IPAddress ip(c.ip);
    j += (i ? "," : ""); j += "{\"ip\":\"" + ip.toString() + "\",\"mac\":\"" + macStr(c.mac) + "\",\"blocked\":" + c.blocked + ",\"allowed\":" + c.allowed + ",\"banned\":" + (c.banned?"true":"false") + "}"; }
  j += "],\"custom\":[";
  for (int i = 0; i < numCustom; i++) { j += (i ? "," : ""); j += "\"" + jesc(customDom[i]) + "\""; }
  j += "]}";
  web.send(200, "application/json", j);
}
static void handleBan() {
  IPAddress ip; if (ip.fromString(web.arg("ip"))) { Dev* c = getClient((uint32_t)ip); if (c) { c->banned = !c->banned; saveBanned(); } }
  web.send(200, "text/plain", "ok");
}


// ---------- blocklist swap (shared by upload + remote fetch) ----------

static const char* BLOCKLIST_NEW_PATH = "/blocklist.new";
static const char* BLOCKLIST_BAK_PATH = "/blocklist.bak";

// Read a 5-byte little-endian hash.
static uint64_t readHash40(const uint8_t* p) {
  uint64_t h = 0;
  for (int i = 0; i < HASH_BYTES; i++) {
    h |= (uint64_t)p[i] << (8 * i);
  }
  return h;
}

// Validate file size and strictly increasing hash order.
static bool validateBlocklist(const char* path) {
  File f = LittleFS.open(path, "r");
  if (!f) return false;

  size_t sz = f.size();

  if (sz == 0 || sz % HASH_BYTES != 0) {
    f.close();
    return false;
  }

  uint8_t buffer[1020]; // 1020 is divisible by 5
  size_t remaining = sz;
  uint64_t previous = 0;
  bool hasPrevious = false;
  bool valid = true;

  while (remaining > 0) {
    size_t chunk = remaining;
    if (chunk > sizeof(buffer)) chunk = sizeof(buffer);

    int n = f.read(buffer, chunk);
    if (n != (int)chunk) {
      valid = false;
      break;
    }

    for (size_t i = 0; i < chunk; i += HASH_BYTES) {
      uint64_t current = readHash40(buffer + i);

      if (hasPrevious && current <= previous) {
        valid = false;
        break;
      }

      previous = current;
      hasPrevious = true;
    }

    if (!valid) break;

    remaining -= chunk;
    yield();
  }

  f.close();
  return valid && remaining == 0;
}

// Reopen the active blocklist and rebuild its PSRAM cache.
static bool reopenBlocklist() {
  if (blocklist) blocklist.close();

  if (psramCache) {
    free(psramCache);
    psramCache = nullptr;
  }

  numHashes = 0;
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");

  if (!blocklist) return false;

  size_t sz = blocklist.size();

  if (sz == 0 || sz % HASH_BYTES != 0) {
    blocklist.close();
    return false;
  }

  numHashes = sz / HASH_BYTES;

  if (psramFound()) {
    psramCache = (uint8_t*)heap_caps_malloc(sz, MALLOC_CAP_SPIRAM);

    if (psramCache) {
      size_t bytesRead = 0;

      while (bytesRead < sz) {
        size_t chunk = sz - bytesRead;
        if (chunk > 4096) chunk = 4096;

        int n = blocklist.read(psramCache + bytesRead, chunk);
        if (n <= 0) break;

        bytesRead += n;
        yield();
      }

      if (bytesRead != sz) {
        Serial.println("[blocklist] PSRAM cache incomplete");
        free(psramCache);
        psramCache = nullptr;
        blocklist.seek(0);
      } else {
        Serial.printf("[blocklist] PSRAM loaded: %u bytes\n",
                      (unsigned)bytesRead);
      }
    }
  }

  return true;
}

// Recover an interrupted replacement after a reboot.
static void recoverBlocklistFiles() {
  bool liveExists = LittleFS.exists(BLOCKLIST_PATH);
  bool backupExists = LittleFS.exists(BLOCKLIST_BAK_PATH);

  if (!liveExists && backupExists) {
    if (LittleFS.rename(BLOCKLIST_BAK_PATH, BLOCKLIST_PATH)) {
      Serial.println("[blocklist] Previous blocklist restored");
    } else {
      Serial.println("[blocklist] WARNING: backup restore failed");
    }
  } else if (liveExists && backupExists) {
    LittleFS.remove(BLOCKLIST_BAK_PATH);
  }
}

// Prepare a temporary file without touching the active blocklist.
static void beginBlocklistSwap() {
  if (LittleFS.exists(BLOCKLIST_NEW_PATH)) {
    LittleFS.remove(BLOCKLIST_NEW_PATH);
  }
}

// Validate and atomically replace the active blocklist with backup recovery.
static bool commitNewBlocklist() {
  if (!validateBlocklist(BLOCKLIST_NEW_PATH)) {
    Serial.println("[blocklist] New file validation failed");
    LittleFS.remove(BLOCKLIST_NEW_PATH);
    return false;
  }

  // Remove an old backup before starting a new transaction.
  if (LittleFS.exists(BLOCKLIST_BAK_PATH)) {
    if (!LittleFS.remove(BLOCKLIST_BAK_PATH)) {
      Serial.println("[blocklist] Cannot remove old backup");
      return false;
    }
  }

  bool hadLive = LittleFS.exists(BLOCKLIST_PATH);

  // Close active file before renaming it.
  if (blocklist) blocklist.close();

  // Keep the old blocklist as a backup.
  if (hadLive && !LittleFS.rename(BLOCKLIST_PATH, BLOCKLIST_BAK_PATH)) {
    Serial.println("[blocklist] Cannot create backup");
    reopenBlocklist();
    return false;
  }

  // Move the validated new file into the active location.
  if (!LittleFS.rename(BLOCKLIST_NEW_PATH, BLOCKLIST_PATH)) {
    Serial.println("[blocklist] New file rename failed");

    if (hadLive) {
      LittleFS.rename(BLOCKLIST_BAK_PATH, BLOCKLIST_PATH);
    }

    reopenBlocklist();
    return false;
  }

  // Reopen the new file and rebuild its cache.
  if (!reopenBlocklist()) {
    Serial.println("[blocklist] Cannot reopen new file");

    LittleFS.remove(BLOCKLIST_PATH);

    if (hadLive) {
      LittleFS.rename(BLOCKLIST_BAK_PATH, BLOCKLIST_PATH);
    }

    reopenBlocklist();
    return false;
  }

  // New blocklist is active. Remove the old backup.
  if (hadLive) {
    LittleFS.remove(BLOCKLIST_BAK_PATH);
  }

  Serial.printf("[blocklist] Update successful: %u hashes\n",
                (unsigned)numHashes);

  return true;
}

// ---------- OTA blocklist update (browser upload) ----------

static bool upOk = false;
static bool upWriteOk = true;
static File upFile;

static void handleUploadDone() {
  web.send(
    upOk ? 200 : 500,
    "text/plain",
    upOk ? "ok" : "rejected: upload incomplete or invalid blocklist"
  );
}

static void handleUpload() {
  HTTPUpload& u = web.upload();

  switch (u.status) {
    case UPLOAD_FILE_START: {
      upOk = false;
      upWriteOk = true;

      beginBlocklistSwap();

      upFile = LittleFS.open(BLOCKLIST_NEW_PATH, "w");

      if (!upFile) {
        upWriteOk = false;
        Serial.println("[upload] Cannot create temporary file");
      }

      Serial.printf("[upload] receiving %s\n", u.filename.c_str());
      break;
    }

    case UPLOAD_FILE_WRITE: {
      if (!upFile || !upWriteOk) {
        upWriteOk = false;
        break;
      }

      size_t written = upFile.write(u.buf, u.currentSize);

      if (written != u.currentSize) {
        upWriteOk = false;
        Serial.println("[upload] Write failed");
      }

      break;
    }

    case UPLOAD_FILE_END: {
      if (upFile) {
        upFile.flush();
        upFile.close();
      }

      if (upWriteOk) {
        upOk = commitNewBlocklist();
      } else {
        LittleFS.remove(BLOCKLIST_NEW_PATH);
        upOk = false;
      }

      Serial.printf(
        "[upload] %s -> %u domains\n",
        upOk ? "OK" : "REJECTED",
        (unsigned)numHashes
      );

      break;
    }

    case UPLOAD_FILE_ABORTED: {
      if (upFile) {
        upFile.close();
      }

      LittleFS.remove(BLOCKLIST_NEW_PATH);

      upOk = false;
      upWriteOk = false;

      Serial.println("[upload] Aborted; old blocklist preserved");
      break;
    }
  }
}


// ---------- remote blocklist auto-update ----------
static void loadUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "r"); if (!f) return;
  updateUrl = f.readStringUntil('\n'); updateUrl.trim();
  String iv = f.readStringUntil('\n'); iv.trim(); if (iv.length()) updateIntervalH = iv.toInt();
  f.close(); if (updateIntervalH < 1) updateIntervalH = 1;
}
static void saveUpdateCfg() {
  File f = LittleFS.open("/update.cfg", "w"); if (!f) return;
  f.println(updateUrl); f.println(updateIntervalH); f.close();
}

static bool fetchBlocklist(String url) {
  url.trim();

  if (!url.length()) {
    updateStatus = "no url set";
    return false;
  }

  Serial.printf("[remote] GET %s\n", url.c_str());

  WiFiClientSecure cs;
  cs.setInsecure();

  WiFiClient cl;
  HTTPClient http;

  http.setTimeout(20000);
  http.setFollowRedirects(HTTPC_STRICT_FOLLOW_REDIRECTS);

  bool https = url.startsWith("https://");

  if (!(https ? http.begin(cs, url) : http.begin(cl, url))) {
    updateStatus = "begin failed";
    return false;
  }

  int code = http.GET();

  if (code != HTTP_CODE_OK) {
    http.end();
    updateStatus = "HTTP " + String(code);
    Serial.printf("[remote] %s\n", updateStatus.c_str());
    return false;
  }

  beginBlocklistSwap();

  File f = LittleFS.open(BLOCKLIST_NEW_PATH, "w");

  if (!f) {
    http.end();
    updateStatus = "fs open failed";
    return false;
  }

  WiFiClient* stream = http.getStreamPtr();

  int contentLength = http.getSize();
  uint8_t buffer[1024];

  size_t total = 0;
  bool writeOk = true;
  bool timedOut = false;

  uint32_t lastDataTime = millis();

  while (true) {
    size_t availableBytes = stream->available();

    if (availableBytes > 0) {
      size_t chunk = availableBytes;

      if (chunk > sizeof(buffer)) {
        chunk = sizeof(buffer);
      }

      int received = stream->readBytes(buffer, chunk);

      if (received <= 0) {
        writeOk = false;
        break;
      }

      size_t written = f.write(buffer, received);

      if (written != (size_t)received) {
        writeOk = false;
        break;
      }

      total += written;
      lastDataTime = millis();

      if (contentLength >= 0 &&
          total > (size_t)contentLength) {
        writeOk = false;
        break;
      }
    } else {
      if (!http.connected()) {
        break;
      }

      if (millis() - lastDataTime > 20000) {
        timedOut = true;
        break;
      }

      delay(2);
    }

    yield();
  }

  f.flush();
  f.close();
  http.end();

  bool complete = writeOk && !timedOut && total > 0;

  if (contentLength >= 0 &&
      total != (size_t)contentLength) {
    complete = false;
  }

  if (!complete) {
    LittleFS.remove(BLOCKLIST_NEW_PATH);

    updateStatus = "download incomplete (" +
                   String(total) + " bytes)";

    Serial.printf("[remote] %s\n", updateStatus.c_str());
    return false;
  }

  bool ok = commitNewBlocklist();

  if (ok) {
    updateStatus = "ok: " + String(numHashes) + " domains";
  } else {
    updateStatus = "blocklist validation or commit failed";
  }

  Serial.printf("[remote] %s\n", updateStatus.c_str());

  return ok;
}


// ---------- firmware OTA (browser upload of firmware.bin -> reboot) ----------
static void handleFwUpdateDone() {
  bool ok = !Update.hasError();
  web.send(ok ? 200 : 500, "text/plain", ok ? "ok, rebooting" : "firmware update failed");
  if (ok) { delay(300); ESP.restart(); }
}
static void handleFwUpload() {
  HTTPUpload& u = web.upload();
  if (u.status == UPLOAD_FILE_START) {
    Serial.printf("[fw-ota] %s\n", u.filename.c_str());
    if (!Update.begin(UPDATE_SIZE_UNKNOWN)) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_WRITE) {
    if (Update.write(u.buf, u.currentSize) != u.currentSize) Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_END) {
    if (Update.end(true)) Serial.printf("[fw-ota] %u bytes OK\n", u.totalSize);
    else Update.printError(Serial);
  } else if (u.status == UPLOAD_FILE_ABORTED) {
    Update.abort(); Serial.println("[fw-ota] aborted");
  }
}

// ---------- WiFi provisioning (captive portal) ----------
// Try provisioned NVS creds first, then the compile-time secrets.h creds as a
// fallback (so the maintainer's own device + source builders keep working). If
// neither connects, fall through to the config portal.
static bool connectWiFi() {
  prefs.begin("wifi", true);
  String ss = prefs.getString("ssid", "");
  String pw = prefs.getString("pass", "");
  prefs.end();
  const char* ssid = ss.length() ? ss.c_str() : WIFI_SSID;
  const char* pass = ss.length() ? pw.c_str() : WIFI_PASS;
  if (!ssid || !*ssid || strcmp(ssid, "YOUR_WIFI_SSID") == 0) return false;  // unconfigured
  Serial.printf("WiFi: connecting to \"%s\"%s\n", ssid, ss.length() ? " (provisioned)" : " (secrets.h)");
  WiFi.mode(WIFI_STA); WiFi.setSleep(false); WiFi.begin(ssid, pass);
  uint32_t t0 = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < 20000) { delay(250); Serial.print("."); }
  Serial.println();
  return WiFi.status() == WL_CONNECTED;
}

static void handlePortalRoot() {
  String html =
    "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
    "<title>C3 AdBlock setup</title>"
    "<body style='font:16px system-ui,sans-serif;max-width:420px;margin:36px auto;padding:0 16px;background:#0d1117;color:#c9d1d9'>"
    "<h2>&#128737; C3 AdBlock &mdash; WiFi setup</h2>"
    "<p style='color:#8b949e'>Pick your network and enter its password. The device restarts and joins it.</p>"
    "<form method=POST action=/wifisave>"
    "<input list=nets name=s placeholder='WiFi name' required style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<datalist id=nets>" + portalOpts + "</datalist>"
    "<input name=p type=password placeholder='Password' style='width:100%;box-sizing:border-box;padding:11px;margin:6px 0;border-radius:6px;border:1px solid #30363d;background:#161b22;color:#c9d1d9'>"
    "<button style='width:100%;padding:12px;margin-top:8px;border-radius:6px;border:0;background:#3fb950;color:#000;font-weight:600;cursor:pointer'>Connect</button>"
    "</form></body>";
  web.send(200, "text/html", html);
}
static void handleWifiSave() {
  String ss = web.arg("s"), pw = web.arg("p");
  if (!ss.length()) { web.send(400, "text/plain", "missing WiFi name"); return; }
  prefs.begin("wifi", false); prefs.putString("ssid", ss); prefs.putString("pass", pw); prefs.end();
  web.send(200, "text/html", "<!doctype html><meta charset=utf-8><body style='font:16px system-ui;text-align:center;margin-top:60px'>"
                             "&#9989; Saved. Restarting and joining <b>" + ss + "</b>&hellip;<br><br>"
                             "Reconnect your phone to your normal WiFi, then find the box at <b>c3adblock.local</b>.</body>");
  delay(900); ESP.restart();
}
// Never returns — blocks in the portal loop until creds are saved (then reboots).
static void startConfigPortal() {
  int n = WiFi.scanNetworks();                 // scan while still in STA mode (no APSTA)
  portalOpts = "";
  for (int i = 0; i < n && i < 15; i++) portalOpts += "<option value='" + jesc(WiFi.SSID(i)) + "'>";
  uint8_t mac[6]; WiFi.macAddress(mac);
  char ap[24]; snprintf(ap, sizeof(ap), "ESP-AdBlock-%02X%02X", mac[4], mac[5]);
  WiFi.mode(WIFI_AP); WiFi.softAP(ap);
  IPAddress apIP = WiFi.softAPIP();
  dnsPortal.start(53, "*", apIP);              // catch-all -> phones pop the captive portal
  web.on("/", handlePortalRoot);
  web.on("/wifisave", HTTP_POST, handleWifiSave);
  web.onNotFound(handlePortalRoot);            // any captive-portal probe -> the form
  web.begin();
  Serial.printf("\n[setup] No WiFi. Join open network \"%s\" and a setup page pops up (or http://%s)\n",
                ap, apIP.toString().c_str());
  while (true) { dnsPortal.processNextRequest(); web.handleClient(); delay(2); }
}


void setup() {
  Serial.begin(115200);
  delay(300);
  Serial.println("\n[esp-adblock] booting");

  // Mount LittleFS without automatic formatting.
  if (!LittleFS.begin(false)) {
    Serial.println("[ERROR] LittleFS mount failed!");
    return;
  }

    // Recover an interrupted blocklist update.
  recoverBlocklistFiles();

  // Load blocklist.
  blocklist = LittleFS.open(BLOCKLIST_PATH, "r");

  if (blocklist) {
    size_t sz = blocklist.size();

    if (sz == 0 || sz % HASH_BYTES != 0) {
      Serial.println("[ERROR] Invalid blocklist size!");
      blocklist.close();
      numHashes = 0;
    } else {
      numHashes = sz / HASH_BYTES;
      Serial.printf("blocklist: %u domains\n", (unsigned)numHashes);

      // Load blocklist into PSRAM when available.
      if (psramFound()) {
        psramCache = (uint8_t*)heap_caps_malloc(sz, MALLOC_CAP_SPIRAM);

        if (psramCache) {
          size_t bytesRead = 0;

          while (bytesRead < sz) {
            size_t chunk = sz - bytesRead;
            if (chunk > 4096) chunk = 4096;

            int r = blocklist.read(psramCache + bytesRead, chunk);
            if (r <= 0) break;

            bytesRead += r;
            yield();
          }

          if (bytesRead != sz) {
            Serial.println("[ERROR] PSRAM cache incomplete!");
            free(psramCache);
            psramCache = nullptr;
            blocklist.seek(0);
          } else {
            Serial.printf("PSRAM cache loaded: %u bytes\n", (unsigned)bytesRead);
          }
        } else {
          Serial.println("PSRAM alloc failed, fallback to Flash");
        }
      }
    }
  } else {
    numHashes = 0;
    Serial.println("[WARN] No blocklist found!");
  }

  loadCustom();
  loadBanned();
  loadUpdateCfg();

  Serial.printf("custom: %d, banned: %d\n", numCustom, numBanned);

  // Hold BOOT (GPIO9) at power-on to wipe saved WiFi.
  pinMode(9, INPUT_PULLUP);

  if (digitalRead(9) == LOW) {
    delay(60);

    if (digitalRead(9) == LOW) {
      prefs.begin("wifi", false);
      prefs.clear();
      prefs.end();
      Serial.println("[setup] BOOT held -> cleared saved WiFi");
    }
  }

  if (!connectWiFi()) startConfigPortal();

  Serial.printf("WiFi up: %s\n", WiFi.localIP().toString().c_str());

  if (MDNS.begin("espadblock")) {
    MDNS.addService("http", "tcp", 80);
    Serial.println("dashboard: http://espadblock.local");
  }

  dnsServer.begin(DNS_PORT);
  upstreamCli.begin(0);

  web.on("/", []() { web.send_P(200, "text/html", PAGE); });
  web.on("/stats.json", handleStats);
  web.on("/ban", handleBan);
  web.on("/addblock", []() {
    addCustom(web.arg("d"));
    web.send(200, "text/plain", "ok");
  });
  web.on("/unblock", []() {
    removeCustom(web.arg("d"));
    web.send(200, "text/plain", "ok");
  });
  web.on("/forgetwifi", []() {
    web.send(200, "text/plain", "cleared — rebooting into setup portal");
    prefs.begin("wifi", false);
    prefs.clear();
    prefs.end();
    delay(500);
    ESP.restart();
  });

  web.on("/upload", HTTP_POST, handleUploadDone, handleUpload);
  web.on("/update", HTTP_POST, handleFwUpdateDone, handleFwUpload);

  web.on("/fetchnow", []() {
    fetchBlocklist(updateUrl);
    web.send(200, "text/plain", updateStatus);
  });

  web.on("/setupdate", []() {
    if (web.hasArg("u")) updateUrl = web.arg("u");

    if (web.hasArg("h")) {
      updateIntervalH = web.arg("h").toInt();
      if (updateIntervalH < 1) updateIntervalH = 1;
    }

    saveUpdateCfg();
    web.send(200, "text/plain", "ok");
  });

  web.begin();

  ArduinoOTA.setHostname("espadblock");
  ArduinoOTA.begin();

  Serial.println("DNS :53 + dashboard :80 + OTA up");
}


void loop() {
  ArduinoOTA.handle();
  web.handleClient();
  bool busy = handleDns();
  if (updateUrl.length()) {               // periodic remote blocklist auto-update
    uint32_t now = millis();
    if (lastCheckMs == 0) lastCheckMs = now;   // skip an immediate fetch on boot
    else if (now - lastCheckMs >= updateIntervalH * 3600000UL) { lastCheckMs = now; fetchBlocklist(updateUrl); }
  }
  if (!busy) delay(1);   // sleep only when idle: full speed under load, cool when quiet
}
