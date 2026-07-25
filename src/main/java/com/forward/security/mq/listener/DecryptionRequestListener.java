package com.forward.security.mq.listener;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.forward.security.model.DecryptionRequest;
import com.forward.security.model.DecryptionResponse;
import com.forward.security.mq.MQConfig;
import com.forward.security.service.FileDecryptionOrchestrator;

import com.ibm.mq.jakarta.jms.MQConnectionFactory;
import com.ibm.msg.client.jakarta.wmq.WMQConstants;

import jakarta.jms.*;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * IBM MQ message listener for {@code SECURITY.SERVICE.REQUEST.QUEUE}.
 *
 * <h2>Inbound message (JSON)</h2>
 * <pre>
 * {
 *   "custId"           : 1001,
 *   "fileS3Path"       : "forward-bank-payments/FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/INCOMING/I1234567890123.FWB.pain00800108.ABCD123.PM.pgp_12345145",
 *   "pgpSigningEnabled": false
 * }
 * </pre>
 *
 * <h2>Outbound message (JSON) written to {@code SECURITY.SERVICE.RESPONSE.QUEUE}</h2>
 * <pre>
 * {
 *   "custId"            : 1001,
 *   "decrypted"         : true,
 *   "decryptedFilePath" : "forward-bank-payments/FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/DECRYPTED/I1234567890123.FWB.pain00800108.ABCD123.PM.xml"
 * }
 * </pre>
 *
 * <p>Consumer and producer use separate JMS connections to prevent producer
 * activity from interfering with consumer session acknowledgment.
 *
 * <p>Lifecycle is managed by Spring via {@code initMethod="start"} and
 * {@code destroyMethod="stop"} in
 * {@link com.forward.security.config.MQListenerConfig}.
 */
public class DecryptionRequestListener implements MessageListener {

    private static final ObjectMapper OBJECT_MAPPER         = new ObjectMapper();
    private static final int          MAX_DELIVERY_ATTEMPTS = 5;

    private final MQConfig                   mqConfig;
    private final FileDecryptionOrchestrator orchestrator;

    private Connection      consumerConnection;
    private Connection      producerConnection;
    private Session         consumerSession;
    private Session         producerSession;
    private MessageConsumer consumer;
    private MessageProducer producer;

    public DecryptionRequestListener(MQConfig mqConfig,
                                     FileDecryptionOrchestrator orchestrator) {
        this.mqConfig     = mqConfig;
        this.orchestrator = orchestrator;
    }

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    public void start() {
        try {
            MQConnectionFactory factory = createFactory();

            // Consumer connection
            consumerConnection = factory.createConnection();
            consumerSession    = consumerConnection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            Queue requestQueue = consumerSession.createQueue(MQConfig.REQUEST_QUEUE);
            consumer           = consumerSession.createConsumer(requestQueue);
            consumer.setMessageListener(this);

            // Producer connection (isolated from consumer)
            producerConnection = factory.createConnection();
            producerSession    = producerConnection.createSession(false, Session.AUTO_ACKNOWLEDGE);
            Queue responseQueue = producerSession.createQueue(MQConfig.RESPONSE_QUEUE);
            producer            = producerSession.createProducer(responseQueue);

            // Start producer first so responses can be sent before messages arrive
            producerConnection.start();
            consumerConnection.start();

            System.out.println("╔══════════════════════════════════════════════════════════╗");
            System.out.println("║  DecryptionRequestListener STARTED                        ║");
            System.out.println("╠══════════════════════════════════════════════════════════╣");
            System.out.println("║  Listening on  : " + MQConfig.REQUEST_QUEUE);
            System.out.println("║  Responding to : " + MQConfig.RESPONSE_QUEUE);
            System.out.println("╚══════════════════════════════════════════════════════════╝");

        } catch (JMSException e) {
            throw new RuntimeException("Failed to start DecryptionRequestListener", e);
        }
    }

    public void stop() {
        closeQuietly(consumer,           "consumer");
        closeQuietly(producer,           "producer");
        closeQuietly(consumerSession,    "consumerSession");
        closeQuietly(producerSession,    "producerSession");
        closeQuietly(consumerConnection, "consumerConnection");
        closeQuietly(producerConnection, "producerConnection");
        System.out.println("✓ DecryptionRequestListener stopped");
    }

    // ── Message handler ───────────────────────────────────────────────────────

    @Override
    public void onMessage(Message message) {
        System.out.println("\n" + "=".repeat(80));
        System.out.println("DecryptionRequestListener: message received");

        String  correlationId = null;
        boolean responseSent  = false;
        Long    custId        = null;

        try {
            // ── Poison-message guard ──────────────────────────────────────────
            int deliveryCount = message.getIntProperty("JMSXDeliveryCount");
            if (deliveryCount > MAX_DELIVERY_ATTEMPTS) {
                System.err.println("✗ POISON MESSAGE — discarding after "
                        + deliveryCount + " delivery attempts. JMSMessageID="
                        + message.getJMSMessageID());
                return;
            }

            if (!(message instanceof TextMessage textMessage)) {
                System.err.println("✗ Unsupported message type: "
                        + message.getClass().getSimpleName());
                return;
            }

            correlationId      = message.getJMSCorrelationID();
            String requestBody = textMessage.getText();

            System.out.println("  JMSMessageID    : " + message.getJMSMessageID());
            System.out.println("  Correlation ID  : " + correlationId);
            System.out.println("  Request Payload : " + requestBody);

            // ── Parse JSON → DecryptionRequest ────────────────────────────────
            DecryptionRequest request;
            try {
                request = OBJECT_MAPPER.readValue(requestBody, DecryptionRequest.class);
            } catch (Exception e) {
                System.err.println("✗ Failed to parse request JSON: " + e.getMessage());
                sendResponse(correlationId,
                        DecryptionResponse.failure(null, "SSE_001",
                                "Invalid request JSON: " + e.getMessage()));
                responseSent = true;
                return;
            }

            custId = request.getCustId();
            System.out.println("  Customer ID     : " + custId);
            System.out.println("  File S3 Path    : " + request.getFileS3Path());
            System.out.println("  PGP Signing     : " + request.isPgpSigningEnabled());

            // ── Delegate to orchestrator ──────────────────────────────────────
            long startMs = System.currentTimeMillis();
            DecryptionResponse response = orchestrator.process(request);
            long elapsedMs = System.currentTimeMillis() - startMs;

            System.out.println("  Processing time : " + elapsedMs + " ms");
            System.out.println("  Result          : " + response);

            sendResponse(correlationId, response);
            responseSent = true;

        } catch (Throwable t) {
            System.err.println("!!! CRITICAL FAILURE in DecryptionRequestListener: "
                    + t.getMessage());
            t.printStackTrace();
        } finally {
            if (!responseSent && correlationId != null) {
                trySendErrorResponse(correlationId, custId,
                        "SSE_INTERNAL_ERROR", "Unexpected error during processing");
            }
            System.out.println("=".repeat(80));
        }
    }

    // ── Response serialisation ────────────────────────────────────────────────

    private void sendResponse(String correlationId,
                               DecryptionResponse response) throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("custId",            response.getCustId());
        payload.put("decrypted",         response.isDecrypted());
        payload.put("decryptedFilePath", nullToEmpty(response.getDecryptedFilePath()));

        // Include error fields only when present — keeps success responses clean
        if (response.getErrorCode() != null && !response.getErrorCode().isBlank()) {
            payload.put("errorCode",    response.getErrorCode());
            payload.put("errorMessage", nullToEmpty(response.getErrorMessage()));
        }

        String payloadJson = OBJECT_MAPPER.writeValueAsString(payload);

        TextMessage responseMessage = producerSession.createTextMessage(payloadJson);
        responseMessage.setJMSCorrelationID(correlationId);
        producer.send(responseMessage);

        System.out.println("  ✓ Response sent to " + MQConfig.RESPONSE_QUEUE);
        System.out.println("    Payload        : " + payloadJson);
        System.out.println("    Correlation ID : " + correlationId);
    }

    private void trySendErrorResponse(String correlationId,
                                       Long custId,
                                       String errorCode,
                                       String errorMessage) {
        try {
            sendResponse(correlationId,
                    DecryptionResponse.failure(custId, errorCode, errorMessage));
        } catch (Exception e) {
            System.err.println("✗ Failed to send error response: " + e.getMessage());
        }
    }

    private String nullToEmpty(String value) {
        return value != null ? value : "";
    }

    // ── MQ factory ────────────────────────────────────────────────────────────

    private MQConnectionFactory createFactory() throws JMSException {
        MQConnectionFactory factory = new MQConnectionFactory();
        factory.setHostName(mqConfig.getHost());
        factory.setPort(mqConfig.getPort());
        factory.setChannel(mqConfig.getChannel());
        factory.setQueueManager(mqConfig.getQueueManager());
        factory.setTransportType(WMQConstants.WMQ_CM_CLIENT);
        return factory;
    }

    // ── Close helpers ─────────────────────────────────────────────────────────

    private void closeQuietly(MessageConsumer c, String name) {
        if (c != null) try { c.close(); } catch (JMSException e) { warn(name, e); }
    }
    private void closeQuietly(MessageProducer p, String name) {
        if (p != null) try { p.close(); } catch (JMSException e) { warn(name, e); }
    }
    private void closeQuietly(Session s, String name) {
        if (s != null) try { s.close(); } catch (JMSException e) { warn(name, e); }
    }
    private void closeQuietly(Connection c, String name) {
        if (c != null) try { c.close(); } catch (JMSException e) { warn(name, e); }
    }
    private void warn(String resource, JMSException e) {
        System.err.println("WARN: Failed to close " + resource + ": " + e.getMessage());
    }
}
