package burp;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.MGF1ParameterSpec;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class InteractshClient {
    private PrivateKey privateKey;
    private String correlationId;
    private String correlationIdNonce;
    private String secretKey;
    private final String serverUrl;
    private final String serverHost;
    private boolean registered;
    private final Set<String> seenIds = new HashSet<>();
    private utils.Logger logger;

    private static final String ZBASE32 = "ybndrfg8ejkmcpqxot1uwisza345h769";
    private static final SecureRandom RNG = new SecureRandom();
    private static final int MAX_SEEN_IDS = 10000;

    public static final String DEFAULT_SERVER = "https://oast.fun";

    public InteractshClient() {
        this(DEFAULT_SERVER);
    }

    public InteractshClient(String serverUrl) {
        this.serverUrl = serverUrl;
        String host;
        try {
            host = URI.create(serverUrl).getHost();
        } catch (Exception e) {
            host = "oast.fun";
        }
        this.serverHost = host;
    }

    public void setLogger(utils.Logger logger) {
        this.logger = logger;
    }

    public void register() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        StringBuilder cb = new StringBuilder(20);
        for (int i = 0; i < 20; i++) {
            int d = RNG.nextInt(36);
            cb.append(d < 10 ? (char) ('0' + d) : (char) ('a' + d - 10));
        }
        this.correlationId = cb.toString();
        StringBuilder nonce = new StringBuilder(13);
        for (int i = 0; i < 13; i++) {
            nonce.append(ZBASE32.charAt(RNG.nextInt(ZBASE32.length())));
        }
        this.correlationIdNonce = nonce.toString();
        this.secretKey = genSecretKey();

        byte[] pubDer = publicKey.getEncoded();
        String b64der = Base64.getEncoder().encodeToString(pubDer);
        String pem = "-----BEGIN PUBLIC KEY-----\n" + b64der + "\n-----END PUBLIC KEY-----\n";
        String b64pem = Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.UTF_8));

        String jsonBody = "{\"public-key\":\"" + b64pem
                + "\",\"secret-key\":\"" + secretKey
                + "\",\"correlation-id\":\"" + correlationId + "\"}";

        String resp = httpPost(serverUrl + "/register", jsonBody);
        if (resp.contains("\"error\"")) {
            String err = extractJsonStr(resp, "error");
            throw new RuntimeException("Registration error: " + (err.isEmpty() ? resp : err));
        }
        this.registered = true;
    }

    private static String genSecretKey() {
        byte[] bytes = new byte[24];
        RNG.nextBytes(bytes);
        StringBuilder sb = new StringBuilder(36);
        for (byte b : bytes) {
            int val = (b & 0xFF) % 36;
            sb.append(val < 10 ? (char) ('0' + val) : (char) ('a' + val - 10));
        }
        return sb.toString();
    }

    public String getFullId() {
        return correlationId + correlationIdNonce;
    }

    public String getPayloadUrl() {
        return registered ? getFullId() + "." + serverHost : null;
    }

    public boolean isRegistered() {
        return registered;
    }

    public synchronized List<InteractionData> poll() throws Exception {
        if (!registered) return Collections.emptyList();

        String resp = httpGet(serverUrl + "/poll?id=" + correlationId + "&secret=" + secretKey);

        String aesKeyB64 = extractJsonStr(resp, "aes_key");
        List<String> dataEntries = extractJsonArr(resp, "data");

        if (aesKeyB64.isEmpty() || dataEntries.isEmpty()) {
            return Collections.emptyList();
        }

        byte[] encryptedAesKey = Base64.getDecoder().decode(aesKeyB64);
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPPadding");
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);
        rsa.init(Cipher.DECRYPT_MODE, privateKey, oaepSpec);
        byte[] aesKey = rsa.doFinal(encryptedAesKey);

        List<InteractionData> results = new ArrayList<>();
        for (String entry : dataEntries) {
            try {
                byte[] ct = decodeBase64(entry);
                if (ct.length < 17) continue;
                byte[] iv = Arrays.copyOfRange(ct, 0, 16);
                byte[] enc = Arrays.copyOfRange(ct, 16, ct.length);

                Cipher aes = Cipher.getInstance("AES/CTR/NoPadding");
                aes.init(Cipher.DECRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));
                byte[] pt = aes.doFinal(enc);

                String decrypted = new String(pt, StandardCharsets.UTF_8);

                if (decrypted.isEmpty() || decrypted.charAt(0) != '{') continue;

                InteractionData id = parseJson(decrypted);
                if (id != null && !"?".equals(id.getType())) {
                    id.setPayload(getFullId() + "." + serverHost);
                    String dedupKey = id.getType() + "|" + id.getClientIp() + "|" + id.getTimestamp() + "|" + id.getId();
                    if (!seenIds.contains(dedupKey)) {
                        if (seenIds.size() >= MAX_SEEN_IDS) {
                            seenIds.clear();
                        }
                        seenIds.add(dedupKey);
                        results.add(id);
                    }
                }
            } catch (Exception e) {
                if (logger != null) logger.error("Failed to decrypt/parse interaction: " + e.getMessage());
            }
        }
        return results;
    }

    private static InteractionData parseJson(String json) {
        if (json == null) return null;
        InteractionData d = new InteractionData();
        String proto = extractJsonStr(json, "protocol");
        d.setType(proto.isEmpty() ? "?" : proto.toUpperCase());
        d.setId(extractJsonStr(json, "unique-id"));
        d.setFullId(extractJsonStr(json, "full-id"));
        d.setClientIp(extractJsonStr(json, "remote-address"));
        d.setTimestamp(extractJsonStr(json, "timestamp"));
        String rawReq = extractJsonStr(json, "raw-request");
        String rawResp = extractJsonStr(json, "raw-response");
        d.setRawRequest(rawReq);
        d.setRawResponse(rawResp);

        String domain = decodeDnsDomain(rawReq);
        if (!domain.isEmpty()) {
            d.setDetail(domain);
        } else if ("HTTP".equals(d.getType())) {
            d.setDetail("(http request)");
        } else if ("SMTP".equals(d.getType())) {
            String to = extractJsonStr(json, "smtp-to");
            d.setDetail(!to.isEmpty() ? "To: " + to : "(smtp)");
        } else {
            d.setDetail(d.getType());
        }

        StringBuilder sb = new StringBuilder();
        sb.append("Type: ").append(d.getType()).append("\n");
        sb.append("Timestamp: ").append(d.getTimestamp()).append("\n");
        sb.append("Client IP: ").append(d.getClientIp()).append("\n");
        sb.append("ID: ").append(d.getId()).append("\n");
        if (d.getFullId() != null && !d.getFullId().isEmpty()) {
            sb.append("Full ID: ").append(d.getFullId()).append("\n");
        }

        if (!domain.isEmpty()) {
            sb.append("\n--- DNS Details ---\n");
            sb.append("Query: ").append(domain).append("\n");
        }
        if (!rawReq.isEmpty()) {
            sb.append("\n--- Raw Request (base64) ---\n").append(rawReq).append("\n");
        }
        if (!rawResp.isEmpty()) {
            sb.append("\n--- Raw Response (base64) ---\n").append(rawResp).append("\n");
        }
        d.setFullDetail(sb.toString());
        return d;
    }

    private static String decodeDnsDomain(String rawReqB64) {
        if (rawReqB64 == null || rawReqB64.isEmpty()) return "";
        try {
            byte[] data = decodeBase64(rawReqB64);
            if (data.length < 13) return "";
            int offset = 12;
            StringBuilder domain = new StringBuilder();
            while (offset < data.length) {
                int len = data[offset] & 0xFF;
                if (len == 0) break;
                offset++;
                if (domain.length() > 0) domain.append(".");
                while (len-- > 0 && offset < data.length) {
                    char c = (char) data[offset++];
                    if (c >= 32 && c <= 126) domain.append(c);
                    else domain.append('.');
                }
            }
            return domain.toString();
        } catch (Exception e) {
            return "";
        }
    }

    private static String extractJsonStr(String json, String key) {
        if (json == null || key == null) return "";
        String search = "\"" + key + "\":\"";
        int start = json.indexOf(search);
        if (start < 0) return "";
        start += search.length();
        StringBuilder val = new StringBuilder();
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '\\') {
                i++;
                if (i >= json.length()) break;
                char esc = json.charAt(i);
                switch (esc) {
                    case 'n': val.append('\n'); break;
                    case 'r': val.append('\r'); break;
                    case 't': val.append('\t'); break;
                    case '"': val.append('"'); break;
                    case '\\': val.append('\\'); break;
                    case '/': val.append('/'); break;
                    case 'u':
                        if (i + 4 < json.length()) {
                            String hex = json.substring(i + 1, i + 5);
                            val.append((char) Integer.parseInt(hex, 16));
                            i += 4;
                        }
                        break;
                    default: val.append(esc);
                }
            } else if (c == '"') break;
            else val.append(c);
        }
        return val.toString();
    }

    private static byte[] decodeBase64(String s) {
        if (s == null || s.isEmpty()) return new byte[0];
        if (s.indexOf('_') >= 0 || s.indexOf('-') >= 0) {
            return Base64.getUrlDecoder().decode(s);
        }
        return Base64.getDecoder().decode(s);
    }

    private static List<String> extractJsonArr(String json, String key) {
        if (json == null || key == null) return Collections.emptyList();
        String search = "\"" + key + "\":";
        int start = json.indexOf(search);
        if (start < 0) return Collections.emptyList();
        start = json.indexOf('[', start + search.length());
        if (start < 0) return Collections.emptyList();
        start++;
        List<String> result = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inStr = false;
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (c == '\\') { i++; continue; }
            if (c == '"') {
                if (inStr) { result.add(cur.toString()); cur.setLength(0); inStr = false; }
                else inStr = true;
                continue;
            }
            if (!inStr && (c == ']' || c == ',')) continue;
            if (inStr) cur.append(c);
        }
        return result;
    }

    private static String httpPost(String urlStr, String body) throws Exception {
        HttpURLConnection c = null;
        try {
            c = openConnection(urlStr);
            c.setRequestMethod("POST");
            c.setRequestProperty("Content-Type", "application/json");
            c.setDoOutput(true);
            try (OutputStream os = c.getOutputStream()) {
                os.write(body.getBytes(StandardCharsets.UTF_8));
            }
            return readBody(c);
        } finally {
            if (c != null) c.disconnect();
        }
    }

    private static String httpGet(String urlStr) throws Exception {
        HttpURLConnection c = null;
        try {
            c = openConnection(urlStr);
            c.setRequestMethod("GET");
            return readBody(c);
        } finally {
            if (c != null) c.disconnect();
        }
    }

    private static HttpURLConnection openConnection(String urlStr) throws Exception {
        HttpURLConnection c = (HttpURLConnection) URI.create(urlStr).toURL().openConnection();
        c.setConnectTimeout(10000);
        c.setReadTimeout(10000);
        return c;
    }

    private static String readBody(HttpURLConnection c) throws Exception {
        int status = c.getResponseCode();
        try (InputStream is = (status >= 200 && status < 300) ? c.getInputStream() : c.getErrorStream()) {
            if (is == null) {
                if (status < 200 || status >= 300) throw new RuntimeException("HTTP " + status);
                return "";
            }
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] tmp = new byte[4096];
            int n;
            while ((n = is.read(tmp)) != -1) buf.write(tmp, 0, n);
            return buf.toString(StandardCharsets.UTF_8);
        }
    }
}
