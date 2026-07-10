package com.forward.security.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.S3Configuration;

import java.net.URI;

/**
 * Provides the S3Client bean.
 *
 * When {@code aws.localstack.enabled=true} the client targets LocalStack at
 * {@code http://localhost:4566} with path-style access — LocalStack does not
 * support virtual-hosted bucket addressing by default.
 *
 * In production ({@code aws.localstack.enabled=false}) the client uses the
 * standard AWS credential chain (env vars, EC2/ECS instance profile, etc.).
 */
@Configuration
public class S3Config {

    @Value("${aws.localstack.enabled:false}")
    private boolean localstackEnabled;

    @Value("${aws.localstack.endpoint:http://localhost:4566}")
    private String localstackEndpoint;

    @Value("${aws.region:us-east-1}")
    private String awsRegion;

    @Value("${aws.accessKeyId:test}")
    private String accessKeyId;

    @Value("${aws.secretAccessKey:test}")
    private String secretAccessKey;

    @Bean
    public S3Client s3Client() {
        Region region = Region.of(awsRegion);

        if (localstackEnabled) {
            System.out.println("╔══════════════════════════════════════════════╗");
            System.out.println("║  S3Client → LocalStack  " + localstackEndpoint + "  ║");
            System.out.println("╚══════════════════════════════════════════════╝");

            return S3Client.builder()
                    .region(region)
                    .endpointOverride(URI.create(localstackEndpoint))
                    .serviceConfiguration(S3Configuration.builder()
                            .pathStyleAccessEnabled(true)
                            .build())
                    .credentialsProvider(StaticCredentialsProvider.create(
                            AwsBasicCredentials.create(accessKeyId, secretAccessKey)))
                    .build();
        }

        return S3Client.builder()
                .region(region)
                .credentialsProvider(DefaultCredentialsProvider.create())
                .build();
    }
}
