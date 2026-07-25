package com.forward.security.s3;

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

    public S3Uploader(S3Client s3Client) {
        this.s3Client = s3Client;
    }

    /**
     * Uploads {@code content} to S3 at the given {@code s3Path}.
     *
     * @param s3Path  full S3 path, including the bucket name as the first
     *                path segment (e.g. {@code "my-bucket/some/key.xml"}).
     *                A leading slash is tolerated and stripped before parsing.
     * @param content bytes to upload
     * @throws S3UploadException on any AWS SDK, network, or malformed-path error
     */
    public void upload(String s3Path, byte[] content) {
        String path = s3Path.startsWith("/") ? s3Path.substring(1) : s3Path;

        int slashIndex = path.indexOf('/');
        if (slashIndex <= 0 || slashIndex == path.length() - 1) {
            throw new S3UploadException(
                    "Invalid s3Path '" + s3Path + "': expected format 'bucket/key'", null);
        }

        String bucket = path.substring(0, slashIndex);
        String key = path.substring(slashIndex + 1);

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