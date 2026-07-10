package com.forward.security.s3;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;

/**
 * Uploads byte arrays to S3.
 *
 * Used to persist the decrypted payment file at a computed output key
 * derived from the original encrypted file path.
 */
@Component
public class S3Uploader {

    private final S3Client s3Client;
    private final String   bucket;

    public S3Uploader(S3Client s3Client,
                      @Value("${aws.s3.bucket:fwb-payments-dev}") String bucket) {
        this.s3Client = s3Client;
        this.bucket   = bucket;
    }

    /**
     * Uploads {@code content} to S3 at the given {@code s3Key}.
     *
     * @param s3Key   bucket-relative destination key
     * @param content bytes to upload
     * @throws S3UploadException on any AWS SDK or network error
     */
    public void upload(String s3Key, byte[] content) {
        String key = s3Key.startsWith("/") ? s3Key.substring(1) : s3Key;
        System.out.println("  [S3Uploader] uploading " + content.length
                + " bytes to s3://" + bucket + "/" + key);
        try {
            PutObjectRequest request = PutObjectRequest.builder()
                    .bucket(bucket)
                    .key(key)
                    .contentType("application/octet-stream")
                    .build();
            s3Client.putObject(request, RequestBody.fromBytes(content));
            System.out.println("  [S3Uploader] ✓ uploaded to s3://" + bucket + "/" + key);
        } catch (S3Exception e) {
            throw new S3UploadException(
                    "S3 upload failed for s3://" + bucket + "/" + key + ": " + e.getMessage(), e);
        } catch (Exception e) {
            throw new S3UploadException(
                    "Unexpected error uploading to s3://" + bucket + "/" + key + ": " + e.getMessage(), e);
        }
    }

    // ── Typed exception ───────────────────────────────────────────────────────

    public static class S3UploadException extends RuntimeException {
        public S3UploadException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
