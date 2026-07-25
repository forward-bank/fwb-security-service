package com.forward.security.s3;

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
 *
 * <p>Both {@link #openStream(String)} and {@link #downloadBytes(String)} take a
 * <b>full S3 path with the bucket name embedded as the first path segment</b>
 * (e.g. the values stored in {@code fileS3Path} / {@code bank_pvt_key_s3_path}
 * columns) — there is no separately configured default bucket; the bucket is
 * always derived from the given path.
 */
@Component
public class S3StreamDownloader {

    private final S3Client s3Client;

    public S3StreamDownloader(S3Client s3Client) {
        this.s3Client = s3Client;
    }

    /**
     * Opens a streaming connection to the S3 object at the given path.
     * The caller MUST close the returned stream after use.
     *
     * <p>{@code s3Path} is a <b>full S3 path that embeds the bucket name as its
     * first path segment</b> — for example
     * {@code "forward-bank-payments/FWB_DIRECT_DEBIT/PAYMENT_FILES/2026/02/04/INCOMING/I1234567890123.FWB.pain00800108.ABCD123.PM.pgp_12345145"},
     * where the bucket is {@code forward-bank-payments} and the object key is
     * everything after the first {@code "/"}. The configured {@code aws.s3.bucket}
     * property is intentionally NOT used for this method — the bucket is derived
     * from the path itself.
     *
     * @param s3Path full path in the form {@code <bucket>/<key...>}
     * @return open {@link InputStream} backed by the S3 response body
     * @throws S3DownloadException if the path is malformed (no bucket segment),
     *                              the object is not found, or an AWS error occurs
     */
    public InputStream openStream(String s3Path) {
        BucketAndKey bk = parseBucketAndKey(s3Path);
        System.out.println("  [S3StreamDownloader] opening stream for s3://" + bk.bucket + "/" + bk.key);
        try {
            GetObjectRequest request = GetObjectRequest.builder()
                    .bucket(bk.bucket)
                    .key(bk.key)
                    .build();
            ResponseInputStream<GetObjectResponse> response = s3Client.getObject(request);
            System.out.println("  [S3StreamDownloader] ✓ stream opened for s3://" + bk.bucket + "/" + bk.key);
            return response;
        } catch (NoSuchKeyException e) {
            throw new S3DownloadException(
                    "S3 object not found: s3://" + bk.bucket + "/" + bk.key, e);
        } catch (S3Exception e) {
            throw new S3DownloadException(
                    "S3 error for s3://" + bk.bucket + "/" + bk.key + ": " + e.getMessage(), e);
        } catch (Exception e) {
            throw new S3DownloadException(
                    "Failed to open stream for s3://" + bk.bucket + "/" + bk.key + ": " + e.getMessage(), e);
        }
    }

    /**
     * Downloads the full object content into a byte array.
     * Suitable for small objects such as PGP key files.
     *
     * <p>Unlike {@link #openStream(String)}, the path passed here (e.g. the value
     * of column {@code bank_pvt_key_s3_path}) is a <b>full S3 path that embeds the
     * bucket name as its first path segment</b> — for example
     * {@code "forward-bank-payments/FWB_DIRECT_DEBIT/KEYS/private_key.asc"}, where
     * the bucket is {@code forward-bank-payments} and the object key is everything
     * after the first {@code "/"}. The configured {@code aws.s3.bucket} property is
     * intentionally NOT used for this method — the bucket is derived from the path
     * itself.
     *
     * @param s3Path full path in the form {@code <bucket>/<key...>}
     * @return full object bytes
     * @throws S3DownloadException if the path is malformed (no bucket segment),
     *                              the object is not found, or an AWS error occurs
     */
    public byte[] downloadBytes(String s3Path) {
        BucketAndKey bk = parseBucketAndKey(s3Path);
        System.out.println("  [S3StreamDownloader] downloading bytes for s3://" + bk.bucket + "/" + bk.key);
        try {
            GetObjectRequest request = GetObjectRequest.builder()
                    .bucket(bk.bucket)
                    .key(bk.key)
                    .build();
            byte[] bytes = s3Client.getObjectAsBytes(request).asByteArray();
            System.out.println("  [S3StreamDownloader] ✓ downloaded " + bytes.length
                    + " bytes from s3://" + bk.bucket + "/" + bk.key);
            return bytes;
        } catch (NoSuchKeyException e) {
            throw new S3DownloadException(
                    "S3 object not found: s3://" + bk.bucket + "/" + bk.key, e);
        } catch (S3Exception e) {
            throw new S3DownloadException(
                    "S3 error for s3://" + bk.bucket + "/" + bk.key + ": " + e.getMessage(), e);
        } catch (Exception e) {
            throw new S3DownloadException(
                    "Failed to download s3://" + bk.bucket + "/" + bk.key + ": " + e.getMessage(), e);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Splits a full S3 path of the form {@code <bucket>/<key...>} into its bucket
     * and key components. The bucket is the substring before the first "/"; the
     * key is everything after it.
     */
    private BucketAndKey parseBucketAndKey(String s3Path) {
        if (s3Path == null || s3Path.isBlank()) {
            throw new S3DownloadException("S3 path must not be null or blank");
        }
        // strip a leading slash if present before splitting, so "/bucket/key" and
        // "bucket/key" behave the same way
        String path = s3Path.startsWith("/") ? s3Path.substring(1) : s3Path;

        int firstSlash = path.indexOf('/');
        if (firstSlash <= 0 || firstSlash == path.length() - 1) {
            throw new S3DownloadException(
                    "S3 path must be in the form <bucket>/<key...>, got: " + s3Path);
        }

        String pathBucket = path.substring(0, firstSlash);
        String pathKey     = path.substring(firstSlash + 1);
        return new BucketAndKey(pathBucket, pathKey);
    }

    private static final class BucketAndKey {
        final String bucket;
        final String key;

        BucketAndKey(String bucket, String key) {
            this.bucket = bucket;
            this.key    = key;
        }
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