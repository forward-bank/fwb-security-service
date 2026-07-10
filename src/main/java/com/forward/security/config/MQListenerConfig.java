package com.forward.security.config;

import com.forward.security.mq.MQConfig;
import com.forward.security.mq.listener.DecryptionRequestListener;
import com.forward.security.service.FileDecryptionOrchestrator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires the IBM MQ listener as a Spring-managed bean.
 *
 * Spring calls {@code start()} after the application context is fully initialised
 * and {@code stop()} during graceful shutdown.
 */
@Configuration
public class MQListenerConfig {

    @Value("${mq.host:localhost}")
    private String host;

    @Value("${mq.port:1414}")
    private int port;

    @Value("${mq.channel:SYSTEM.DEF.SVRCONN}")
    private String channel;

    @Value("${mq.queueManager:MY.TEST.QMNGR}")
    private String queueManager;

    @Bean
    public MQConfig mqConfig() {
        return new MQConfig(host, port, channel, queueManager);
    }

    @Bean(initMethod = "start", destroyMethod = "stop")
    public DecryptionRequestListener decryptionRequestListener(
            MQConfig mqConfig,
            FileDecryptionOrchestrator orchestrator) {
        return new DecryptionRequestListener(mqConfig, orchestrator);
    }
}
