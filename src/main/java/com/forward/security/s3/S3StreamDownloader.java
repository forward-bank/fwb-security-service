package com.forward.security.s3;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.NoSuchKeyException;
import software.amazon.awssdk.services.s3.model.S3Exception;

import java.io.InputStream;

/**
 * Provides S3 object access as streaming {@link InputStream}s.
 *
 * For the encrypted payment file we intentionally return a raw streaming
 * {@code InputStream} instead of loading the whole object into memory —
 * payment files can be very large (tens of megabytes) and Bouncy Castle's
 * PGP API works natively with streams.
 *
 * The caller is responsible for closing the returned stream.
 *
 * For small objects (PGP key files), a convenience method {@code downloadBytes}
 * returns the full content as a byte array.
 */
@Component
public class S3StreamDownloader {

    private final S3Client s3Client;
    private final String   bucket;

    public S3StreamDownloader(S3Client s3Client,
                              @Value("${aws.s3.bucket:fwb-payments-dev}") String bucket) {
        this.s3Client = s3Client;
        this.bucket   = bucket;
    }

    /**
     * Opens a streaming connection to the S3 object at the given key.
     * The caller MUST close the returned stream after use.
     *
     * @param s3Key bucket-relative object key (no s3:// prefix, no leading slash)
     * @return open {@link InputStream} backed by the S3 response body
     * @throws S3DownloadException if the key is invalid, object not found, or AWS error occurs
     */
    public InputStream openStream(String s3Key) {
        String key = normaliseKey(s3Key);
        System.out.println("  [S3StreamDownloader] opening stream for s3://" + bucket + "/" + key);
        try {
            GetObjectRequest request = GetObjectRequest.builder()
                    .bucket(bucket)
                    .key(key)
                    .build();
            ResponseInputStream<GetObjectResponse> response = s3Client.getObject(request);
            System.out.println("  [S3StreamDownloader] ✓ stream opened for s3://" + bucket + "/" + key);
            return response;
        } catch (NoSuchKeyException e) {
            throw new S3DownloadException(
                    "S3 object not found: s3://" + bucket + "/" + key, e);
        } catch (S3Exception e) {
            throw new S3DownloadException(
                    "S3 error for s3://" + bucket + "/" + key + ": " + e.getMessage(), e);
        } catch (Exception e) {
            throw new S3DownloadException(
                    "Failed to open stream for s3://" + bucket + "/" + key + ": " + e.getMessage(), e);
        }
    }

    /**
     * Downloads the full object content into a byte array.
     * Suitable for small objects such as PGP key files.
     *
     * @param s3Key bucket-relative object key
     * @return full object bytes
     */
    public byte[] downloadBytes(String s3Key) {
        String key = normaliseKey(s3Key);
        System.out.println("  [S3StreamDownloader] downloading bytes for s3://" + bucket + "/" + key);
        try {
            GetObjectRequest request = GetObjectRequest.builder()
                    .bucket(bucket)
                    .key(key)
                    .build();
            byte[] bytes = s3Client.getObjectAsBytes(request).asByteArray();
            System.out.println("  [S3StreamDownloader] ✓ downloaded " + bytes.length
                    + " bytes from s3://" + bucket + "/" + key);
            return bytes;
        } catch (NoSuchKeyException e) {
            throw new S3DownloadException(
                    "S3 object not found: s3://" + bucket + "/" + key, e);
        } catch (S3Exception e) {
            throw new S3DownloadException(
                    "S3 error for s3://" + bucket + "/" + key + ": " + e.getMessage(), e);
        } catch (Exception e) {
            throw new S3DownloadException(
                    "Failed to download s3://" + bucket + "/" + key + ": " + e.getMessage(), e);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String normaliseKey(String key) {
        if (key == null || key.isBlank()) {
            throw new S3DownloadException("S3 key must not be null or blank");
        }
        // S3 keys must not begin with "/"
        return key.startsWith("/") ? key.substring(1) : key;
    }

    // ── Typed exception ───────────────────────────────────────────────────────

    public static class S3DownloadException extends RuntimeException {
        public S3DownloadException(String message) {
            super(message);
        }
        public S3DownloadException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
