package com.forward.security.repository;

import com.forward.security.entity.CustomerKeyConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data repository for {@link CustomerKeyConfig}.
 *
 * Used to look up a customer's key configuration (S3 paths for PGP keys,
 * Base64-encoded passphrase for the bank's private key) given a customer ID.
 */
@Repository
public interface CustomerKeyConfigRepository extends JpaRepository<CustomerKeyConfig, String> {
    // findById(customerId) provided by JpaRepository is sufficient.
}
