package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import utils.Logger;

public class BurpExtender implements BurpExtension {
    private Logger logger;
    private MontoyaApi api;
    private InteractshSession clientWrapper;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logger = new Logger(api.logging());

        api.extension().setName("Community Collaborator");

        this.clientWrapper = new InteractshSession();
        this.clientWrapper.setLogger(logger);

        api.userInterface().registerSuiteTab("Community Collaborator",
                new CollabSuiteTab(api, clientWrapper, logger));

        logger.info("Interactsh Integration loaded successfully.");
    }
}
