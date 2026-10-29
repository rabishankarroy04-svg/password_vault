package com.securevault.threat;
import org.junit.jupiter.api.*;import org.springframework.jdbc.core.JdbcTemplate;import org.springframework.jdbc.datasource.DriverManagerDataSource;import org.springframework.jdbc.datasource.DataSourceTransactionManager;import org.springframework.transaction.support.TransactionTemplate;import org.springframework.mock.env.MockEnvironment;
import java.util.*;import java.time.*;import com.securevault.admin.*;import static org.junit.jupiter.api.Assertions.*;
class ThreatPostgresIT {
 JdbcTemplate jdbc;ThreatTelemetry telemetry;TransactionTemplate tx;AdminService admin;UUID user;String ip="8.8.8.8";
 @BeforeEach void setup(){
  String url=System.getenv("SECUREVAULT_TEST_PG_URL"),password=System.getenv("SECUREVAULT_TEST_PG_PASSWORD");
  if(url==null||!url.matches("jdbc:postgresql://127\\.0\\.0\\.1:[0-9]+/securevault_test"))throw new IllegalStateException("Disposable loopback test database required");
  var ds=new DriverManagerDataSource(url,"postgres",password);jdbc=new JdbcTemplate(ds);
  assertEquals("securevault-isolated-verification",jdbc.queryForObject("SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname=current_database()",String.class));
  jdbc.execute("TRUNCATE users CASCADE");jdbc.execute("TRUNCATE audit_logs,security_events CASCADE");
  tx=new TransactionTemplate(new DataSourceTransactionManager(ds));telemetry=new ThreatTelemetry(jdbc,new RiskPolicy(new MockEnvironment()),new ConfiguredLocationProvider(""),5,5,15);admin=new AdminService(jdbc,900);
  user=UUID.randomUUID();jdbc.update("INSERT INTO users(id,username,email,password_hash,vault_key_salt) VALUES (?,'fixture','fixture@test.invalid','not-a-real-password','fixture-salt')",user);
 }
 void atomic(Runnable run){tx.executeWithoutResult(status->run.run());}
 UUID alert(){return jdbc.queryForObject("SELECT id FROM security_events ORDER BY timestamp DESC LIMIT 1",UUID.class);}
 UUID audit(String action,String result){return telemetry.audit(user,action,result,ip,"Isolated test action",Map.of());}
 @Test void failedCountMatchesEvidenceAndEscalatesSameIncident(){
  atomic(()->{for(int i=0;i<4;i++){audit("LOGIN_FAILURE","FAILURE");telemetry.failed(user,ip,4,5);}});
  var event=admin.securityEvent(alert());assertEquals(4,event.relatedEvents().size());assertEquals(4,event.event().relatedEventCount());assertTrue(event.event().detectionReason().contains("threshold 4"));
  atomic(()->{for(int i=0;i<2;i++){audit("LOGIN_FAILURE","FAILURE");telemetry.failed(user,ip,4,5);}});
  assertEquals(1,jdbc.queryForObject("SELECT COUNT(*) FROM security_events",Integer.class));event=admin.securityEvent(alert());assertEquals("CRITICAL",event.event().severity());assertEquals(6,event.relatedEvents().size());assertEquals(6,event.event().relatedEventCount());assertTrue(event.event().detectionReason().contains("escalation threshold 6"));
 }
 @Test void outsideWindowAndDifferentSourcesNeverBecomeSupportingEvidence(){
  jdbc.update("INSERT INTO audit_logs(user_id,action_type,status,ip_address,timestamp) VALUES (?,'LOGIN_FAILURE','FAILURE',?,CURRENT_TIMESTAMP-INTERVAL '1 hour')",user,ip);
  atomic(()->{for(int i=0;i<4;i++)audit("LOGIN_FAILURE","FAILURE");telemetry.failed(user,ip,4,5);});
  UUID id=alert();audit("LOGIN_FAILURE","FAILURE");assertEquals(4,admin.securityEvent(id).relatedEvents().size());assertEquals(4,admin.securityEvent(id).event().relatedEventCount());
 }
 @Test void ordinarySuccessAndFirstDeviceDoNotRaiseAlertsButMetadataIsAvailable(){
  atomic(()->telemetry.login(user,ip,"Windows Chrome/120",UUID.randomUUID(),true,true,false));
  atomic(()->telemetry.login(user,ip,"Windows Chrome/120",UUID.randomUUID(),false,false,false));
  assertEquals(0,jdbc.queryForObject("SELECT COUNT(*) FROM security_events",Integer.class));
  assertEquals(2,jdbc.queryForObject("SELECT COUNT(*) FROM audit_logs WHERE action_type='LOGIN'",Integer.class));
  assertEquals("Windows",jdbc.queryForObject("SELECT context->>'os' FROM audit_logs LIMIT 1",String.class));
 }
 @Test void combinedNoveltyCreatesOneExplainableAlertNotThree(){
  atomic(()->audit("LOGIN","SUCCESS"));
  atomic(()->telemetry.login(user,"1.1.1.1","Android Mobile Chrome/120",UUID.randomUUID(),true,true,true));
  assertEquals(1,jdbc.queryForObject("SELECT COUNT(*) FROM security_events",Integer.class));
  var event=admin.securityEvent(alert());assertEquals("COMBINED_LOGIN_RISK",event.event().eventType());assertEquals("HIGH",event.event().severity());assertEquals(1,event.relatedEvents().size());assertTrue(event.event().detectionContext().toString().contains("Mobile"));assertFalse(event.event().detectionContext().toString().contains("password"));
 }
 @Test void repeatedDenialsUseAuditAndDeduplicateAlerts(){
  atomic(()->{for(int i=0;i<8;i++)telemetry.denied(ip,"Linux Firefox/120");});
  assertEquals(8,jdbc.queryForObject("SELECT COUNT(*) FROM audit_logs",Integer.class));assertEquals(1,jdbc.queryForObject("SELECT COUNT(*) FROM security_events",Integer.class));
  var details=admin.securityEvent(alert());assertEquals(5,details.relatedEvents().size());assertEquals(5,details.event().relatedEventCount());
 }
 @Test void sharingNormalActivityIsNotThreatButBurstIs(){
  atomic(()->audit("CREDENTIAL_SHARED","SUCCESS"));assertEquals(0,jdbc.queryForObject("SELECT COUNT(*) FROM security_events",Integer.class));
  atomic(()->{for(int i=0;i<4;i++)audit("CREDENTIAL_SHARED","SUCCESS");});
  var e=admin.securityEvent(alert());assertEquals("CREDENTIAL_SHARED",e.event().eventType());assertEquals(5,e.relatedEvents().size());assertEquals(5,e.event().relatedEventCount());
 }
 @Test void privilegeEscalationHasOneSupportingRecordAndAuditNotesPersist(){
  atomic(()->telemetry.audit(user,"USER_ROLE_CHANGED","SUCCESS",ip,"Role elevated",Map.of("permissionEscalation",true)));
  UUID id=alert();var event=admin.securityEvent(id);assertEquals(1,event.relatedEvents().size());assertEquals(1,event.event().relatedEventCount());
  var actor=new AdminPrincipal(user,UUID.randomUUID(),UUID.randomUUID(),"reviewer","reviewer@test.invalid");
  atomic(()->admin.updateSecurityEventStatus(id,"INVESTIGATING","Owner verification pending",actor,ip));
  atomic(()->admin.updateSecurityEventStatus(id,"FALSE_POSITIVE","Authorized maintenance",actor,ip));
  event=admin.securityEvent(id);assertEquals("FALSE_POSITIVE",event.event().status());assertTrue(event.event().resolved());assertEquals(2,event.history().size());assertTrue(event.history().stream().anyMatch(h->h.notes().equals("Authorized maintenance")));
 }
 @Test void repeatedVaultDenialsAndVaultBurstsHaveRealAuditEvidence(){
  atomic(()->{for(int i=0;i<5;i++)audit("VAULT_ACCESS_DENIED","FAILURE");});assertEquals("VAULT_ACCESS_DENIED",admin.securityEvent(alert()).event().eventType());
  atomic(()->{for(int i=0;i<20;i++)audit("VAULT_READ","SUCCESS");});
  UUID burst=jdbc.queryForObject("SELECT id FROM security_events WHERE event_type='SUSPICIOUS_VAULT_ACCESS'",UUID.class);
  assertEquals(20,admin.securityEvent(burst).relatedEvents().size());
 }
 @Test void auditDateSearchTypeSortPaginationAndDashboardTotalsAgree(){
  atomic(()->{for(int i=0;i<4;i++){audit("LOGIN_FAILURE","FAILURE");telemetry.failed(user,ip,4,5);}});
  LocalDate today=LocalDate.now(ZoneOffset.UTC);var page=admin.activities("fixture",0,2,today,today,"LOGIN_FAILURE","OLDEST");assertEquals(4,page.total(),()->"Expected date="+today+" audit="+jdbc.queryForList("SELECT l.action_type,l.timestamp,u.username FROM audit_logs l LEFT JOIN users u ON u.id=l.user_id"));assertEquals(2,page.items().size());
  assertEquals(2,admin.activities("fixture",1,2,today,today,"LOGIN_FAILURE","NEWEST").items().size());
  assertEquals(0,admin.activities("",0,10,today.minusDays(2),today.minusDays(1),"ALL","NEWEST").total());
  var a=admin.analytics(today,today,"","ALL","ALL",0,10,"NEWEST");assertEquals(4,a.summary().failedLoginAttempts());assertEquals(1,a.summary().totalAlerts());assertEquals(1,a.rangeMetrics().byThreatType().get("MULTIPLE_FAILED_LOGINS"));
  assertThrows(org.springframework.web.server.ResponseStatusException.class,()->admin.activities("",0,10,today,today.minusDays(1),"ALL","NEWEST"));
  assertThrows(org.springframework.web.server.ResponseStatusException.class,()->admin.activities("",0,10,today,today,"';DROP TABLE users","NEWEST"));
 }
 @Test void legacyEvidenceDoesNotInventHistoricalThresholds(){
  jdbc.update("INSERT INTO security_events(user_id,event_type,severity,risk_score,ip_address) VALUES (?,'LEGACY_PERMISSION','MEDIUM',50,?)",user,ip);
  var e=admin.securityEvent(alert());assertEquals(1,e.event().relatedEventCount());assertEquals(1,e.relatedEvents().size());assertTrue(e.event().detectionContext().isEmpty());assertTrue(e.relatedEvents().get(0).details().contains("unavailable"));
 }
 @Test void sensitiveUserAgentAndDeviceHeadersNeverEnterAuditMetadata(){
  var metadata=telemetry.metadata("Windows Chrome/120 PASSWORD=forbidden JWT=forbidden",null,"Unknown",ip);
  atomic(()->telemetry.audit(user,"LOGIN_FAILURE","FAILURE",ip,"Rejected",metadata));
  String stored=jdbc.queryForObject("SELECT context::text FROM audit_logs LIMIT 1",String.class);assertFalse(stored.contains("forbidden"));assertFalse(stored.contains("PASSWORD"));assertTrue(stored.contains("Windows"));
 }
 @Test void applicationRoleCannotRewriteAuditHistory(){
  atomic(()->audit("LOGIN","SUCCESS"));
  assertThrows(org.springframework.dao.DataAccessException.class,()->atomic(()->{jdbc.execute("SET LOCAL ROLE securevault_app");jdbc.execute("DELETE FROM audit_logs");}));
  assertThrows(org.springframework.dao.DataAccessException.class,()->atomic(()->{jdbc.execute("SET LOCAL ROLE securevault_app");jdbc.execute("DELETE FROM security_events");}));
  assertEquals(1,jdbc.queryForObject("SELECT COUNT(*) FROM audit_logs",Integer.class));
 }
 @Test void distinctNewRecipientsEscalateAtConfiguredThreshold(){
  atomic(()->{for(int i=0;i<3;i++)telemetry.audit(user,"CREDENTIAL_SHARED","SUCCESS",ip,"Isolated share",Map.of("recipientRef",UUID.randomUUID().toString(),"recipientIsNew",true));});
  var e=admin.securityEvent(alert());assertEquals("HIGH",e.event().severity());assertEquals(3,e.relatedEvents().size());assertEquals(3,((Number)e.event().detectionContext().get("newRecipientCount")).intValue());
 }
 @Test void reliableLocationNoveltyIsComparedWithHistoryAndNetworkWeightIsCountedOnce(){
  var known=Map.<String,Object>of("locationAvailable",true,"country","US","region","FixtureA");
  atomic(()->telemetry.audit(user,"LOGIN","SUCCESS",ip,"Baseline",known));
  LocationProvider provider=address->Optional.of(new LocationProvider.Location("CA","FixtureB","Isolated test provider"));
  var detector=new ThreatTelemetry(jdbc,new RiskPolicy(new MockEnvironment()),provider,5,5,15);
  atomic(()->detector.login(user,"1.1.1.1","Windows Chrome/120",UUID.randomUUID(),true,true,false));
  var e=admin.securityEvent(alert());assertTrue(e.event().detectionContext().get("riskFactors").toString().contains("UNFAMILIAR_LOCATION"));
  assertFalse(e.event().detectionContext().get("riskFactors").toString().contains("NEW_IP_LOGIN"));assertEquals(45,e.event().riskScore());
 }

 @Test void sameRecipientBelowSharingThresholdDoesNotRaiseThreat(){
  atomic(()->{for(int i=0;i<3;i++)telemetry.audit(user,"CREDENTIAL_SHARED","SUCCESS",ip,"Isolated repeated recipient",Map.of("recipientRef","same-test-reference","recipientIsNew",true));});
  assertEquals(0,jdbc.queryForObject("SELECT COUNT(*) FROM security_events",Integer.class));
 }

 @Test void repeatedMfaFailureEscalatesOneIncidentAndRetainsMatchingEvidence(){
  atomic(()->{for(int i=0;i<3;i++)audit("LOGIN_MFA_FAILURE","FAILURE");var ids=telemetry.ids(user,ip,"LOGIN_MFA_FAILURE",5);telemetry.raise(user,ip,"MFA_FAILURE","HIGH",75,"Three verification failures",Map.of("threshold",3,"windowMinutes",5),ids,5);});
  atomic(()->{for(int i=0;i<2;i++)audit("LOGIN_MFA_FAILURE","FAILURE");var ids=telemetry.ids(user,ip,"LOGIN_MFA_FAILURE",5);telemetry.raise(user,ip,"MFA_FAILURE","CRITICAL",100,"Five verification failures",Map.of("threshold",3,"windowMinutes",5),ids,5);});
  assertEquals(1,jdbc.queryForObject("SELECT COUNT(*) FROM security_events",Integer.class));var e=admin.securityEvent(alert());assertEquals("CRITICAL",e.event().severity());assertEquals(5,e.event().relatedEventCount());assertEquals(5,e.relatedEvents().size());
 }

}
