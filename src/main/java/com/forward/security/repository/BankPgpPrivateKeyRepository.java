package com.forward.security.repository;

import com.forward.security.entity.BankPgpPrivateKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data JPA repository for {@link BankPgpPrivateKey}.
 */
@Repository
public interface BankPgpPrivateKeyRepository extends JpaRepository<BankPgpPrivateKey, Long> {
}
