package burp;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

public class InteractshSession {
    private InteractshClient client;
    private utils.Logger logger;
    private final AtomicInteger payloadCount = new AtomicInteger(0);
    private String lastUrl;

    public void setLogger(utils.Logger logger) {
        this.logger = logger;
    }

    public boolean isAvailable() {
        return true;
    }

    public String getError() {
        return null;
    }

    public synchronized String generatePayload() throws Exception {
        if (client == null) {
            client = new InteractshClient();
            if (logger != null) client.setLogger(logger);
            client.register();
        }
        payloadCount.incrementAndGet();
        String url = client.getPayloadUrl();
        if (url == null || url.isEmpty()) {
            throw new IllegalStateException("Generated payload URL is empty");
        }
        lastUrl = url;
        return url;
    }

    public List<InteractionData> pollInteractions() throws Exception {
        if (client == null) return new ArrayList<>();
        return client.poll();
    }

    public List<String> getPayloadUrls() {
        List<String> urls = new ArrayList<>();
        int count = payloadCount.get();
        String u = client != null ? client.getPayloadUrl() : null;
        if (u == null) return urls;
        for (int i = 0; i < count; i++) {
            urls.add(u);
        }
        return urls;
    }

    public int getPayloadCount() {
        return payloadCount.get();
    }

    public String getLatestPayloadUrl() {
        return lastUrl;
    }
}
