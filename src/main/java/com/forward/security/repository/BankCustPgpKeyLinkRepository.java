package com.forward.security.repository;

import com.forward.security.entity.BankCustPgpKeyLink;
import com.forward.security.entity.BankPgpPrivateKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Spring Data JPA repository for {@link BankCustPgpKeyLink}.
 */
@Repository
public interface BankCustPgpKeyLinkRepository extends JpaRepository<BankCustPgpKeyLink, Long> {

    /**
     * Finds the active key link for a given customer ID.
     */
    Optional<BankCustPgpKeyLink> findFirstByCustIdAndKeyActiveFlag(Long custId, String keyActiveFlag);

    /**
     * Joins {@code FWB_MST_BANK_CUST_PGP_KEY_LINK} with
     * {@code FWB_MST_BANK_PGP_PRIVATE_KEY} on {@code BANK_KEY_SEQ} and returns
     * the active {@link BankPgpPrivateKey} for the given customer.
     *
     * <p>Equivalent SQL:
     * <pre>
     *   SELECT k.*
     *   FROM FWB_MST_BANK_CUST_PGP_KEY_LINK l
     *   JOIN FWB_MST_BANK_PGP_PRIVATE_KEY k ON l.bank_key_seq = k.bank_key_seq
     *   WHERE l.cust_id = :custId AND l.key_active_flag = 'Y'
     *   LIMIT 1
     * </pre>
     *
     * @param custId numeric customer identifier
     * @return the active bank private key linked to the customer, or empty if not found
     */
    @Query("""
            SELECT k FROM BankPgpPrivateKey k
            JOIN BankCustPgpKeyLink l ON l.bankKeySeq = k.bankKeySeq
            WHERE l.custId = :custId
              AND l.keyActiveFlag = 'Y'
            """)
    Optional<BankPgpPrivateKey> findActiveBankKeyByCustId(@Param("custId") Long custId);
}
