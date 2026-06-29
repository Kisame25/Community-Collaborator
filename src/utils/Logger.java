package utils;

import burp.api.montoya.logging.Logging;

public class Logger {
    private final Logging logging;

    public Logger(Logging logging) {
        this.logging = logging;
    }

    public void info(String message) {
        logging.logToOutput("[INFO] " + message);
    }

    public void error(String message) {
        logging.logToError("[ERROR] " + message);
    }
}
