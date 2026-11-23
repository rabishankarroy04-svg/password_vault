package com.securevault.vault;
import com.securevault.threat.ThreatTelemetry;
import java.util.*;
import org.springframework.stereotype.Service;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.transaction.annotation.Transactional;
@Service
public class ShareExpiryService {
    private final JdbcTemplate db;private final ThreatTelemetry telemetry;
    public ShareExpiryService(JdbcTemplate db,ThreatTelemetry telemetry){this.db=db;this.telemetry=telemetry;}
    @Transactional
    public int expire(){
        var rows=db.query("SELECT id,credential_id,shared_by_user_id,shared_with_user_id FROM sharing WHERE status='ACTIVE' AND expires_at<=CURRENT_TIMESTAMP ORDER BY expires_at LIMIT 200 FOR UPDATE SKIP LOCKED",
                (r,n)->new UUID[]{r.getObject(1,UUID.class),r.getObject(2,UUID.class),r.getObject(3,UUID.class),r.getObject(4,UUID.class)});
        for(UUID[] s:rows){
            db.update("UPDATE sharing SET status='EXPIRED' WHERE id=?",s[0]);
            telemetry.audit(s[2],"SHARE_EXPIRED","SUCCESS","system","Shared access expired; credential values omitted",
                    Map.of("shareRef",s[0].toString(),"credentialRef",s[1].toString(),"recipientRef",s[3].toString(),"source","expiry-maintenance"));
        }

        var extRows = db.query("""
                SELECT id, sender_id, credential_id, recipient FROM external_shares
                WHERE expires_at <= CURRENT_TIMESTAMP AND delivery = 'SUBMITTED'
                  AND revoked_at IS NULL AND consumed_at IS NULL
                ORDER BY expires_at LIMIT 200 FOR UPDATE SKIP LOCKED
                """, (r, n) -> new Object[]{
                    r.getObject("id", UUID.class),
                    r.getObject("sender_id", UUID.class),
                    r.getObject("credential_id", UUID.class),
                    r.getString("recipient")
                });
        for (Object[] s : extRows) {
            UUID shareId = (UUID) s[0];
            UUID senderId = (UUID) s[1];
            UUID credId = (UUID) s[2];
            String recipient = (String) s[3];
            db.update("UPDATE external_shares SET delivery='EXPIRED', otp_hash=NULL, grant_hash=NULL WHERE id=?", shareId);
            telemetry.audit(senderId, "EXTERNAL_SHARE_EXPIRED", "SUCCESS", "system",
                    "External share access expired; secret values omitted",
                    Map.of("shareRef", shareId.toString(), "credentialRef", credId.toString(),
                            "recipientRef", recipient, "source", "expiry-maintenance"));
        }
        return rows.size() + extRows.size();
    }
}
