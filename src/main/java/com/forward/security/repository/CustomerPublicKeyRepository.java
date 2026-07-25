package com.forward.security.repository;

import com.forward.security.entity.CustomerPublicKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Spring Data JPA repository for {@link CustomerPublicKey}.
 */
@Repository
public interface CustomerPublicKeyRepository extends JpaRepository<CustomerPublicKey, Long> {

    /**
     * Finds an active customer public key for the given customer ID.
     * Used when {@code pgpSigningEnabled=true} to download the customer's
     * public key from S3 for signature verification.
     */
    Optional<CustomerPublicKey> findFirstByCustIdAndKeyActiveFlag(Long custId, String keyActiveFlag);
}
