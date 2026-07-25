package com.forward.security.mq;

/**
 * Holds IBM MQ connection parameters and queue name constants for the security service.
 */
public class MQConfig {

    private final String host;
    private final int    port;
    private final String channel;
    private final String queueManager;

    /** Inbound: receives decryption requests. */
    public static final String REQUEST_QUEUE  = "SECURITY.SERVICE.REQUEST.QUEUE";

    /** Outbound: sends decryption results. */
    public static final String RESPONSE_QUEUE = "SECURITY.SERVICE.RESPONSE.QUEUE";

    public MQConfig(String host, int port, String channel, String queueManager) {
        this.host         = host;
        this.port         = port;
        this.channel      = channel;
        this.queueManager = queueManager;
    }

    public String getHost()         { return host; }
    public int    getPort()         { return port; }
    public String getChannel()      { return channel; }
    public String getQueueManager() { return queueManager; }
}
