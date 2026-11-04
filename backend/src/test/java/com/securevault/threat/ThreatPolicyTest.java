package com.securevault.threat;
import org.junit.jupiter.api.*;import org.junit.jupiter.api.io.TempDir;import org.springframework.mock.env.MockEnvironment;
import java.nio.file.*;import java.time.*;import java.util.*;import static org.junit.jupiter.api.Assertions.*;
class ThreatPolicyTest {
 @Test void absentUnknownAndApiAgentsAreDistinct(){
  assertEquals("MISSING",DeviceMetadata.parse(null).userAgentStatus());
  assertEquals("MISSING",DeviceMetadata.parse("  ").userAgentStatus());
  assertEquals("UNRECOGNIZED",DeviceMetadata.parse("unidentified-client").userAgentStatus());
  for(String agent:List.of("curl/8.1","PostmanRuntime/7","python-requests/2","Java/17 Linux")){
   var d=DeviceMetadata.parse(agent);assertEquals("NON_BROWSER",d.userAgentStatus());
   assertEquals("Unknown",d.os());assertEquals("Unknown",d.category());
  }
  assertEquals("BROWSER",DeviceMetadata.parse("Mozilla Windows NT 10.0 Chrome/120").userAgentStatus());
 }
 @TempDir Path temp;
 @Test void desktopBrowserAndOsAreCoarseLabels(){var m=DeviceMetadata.parse("Mozilla Windows NT 10.0 Chrome/120 Edg/120");assertEquals("Edge",m.browser());assertEquals("Windows",m.os());assertEquals("Desktop/Laptop",m.category());}
 @Test void phoneTabletAndUnknownHandledWithoutPhysicalModelClaims(){assertEquals("Mobile",DeviceMetadata.parse("iPhone Mobile Safari/1").category());assertEquals("Tablet",DeviceMetadata.parse("Android Safari/1").category());assertEquals("Unknown",DeviceMetadata.parse(null).os());assertEquals("Firefox",DeviceMetadata.parse("Linux Firefox/123").browser());}
 @Test void combinedFactorsEscalateWithoutDoubleCountingNetworkNovelty(){var p=new RiskPolicy(new MockEnvironment());var risk=p.assess(true,true,true,true);assertEquals(65,risk.score());assertEquals("HIGH",risk.severity());assertEquals(3,risk.factors().size());assertFalse(risk.factors().contains("NEW_IP_LOGIN"));assertTrue(risk.explanation().contains("critical=85"));assertTrue(risk.explanation().contains("not a confirmed attack"));}
 @Test void ordinarySuccessIsNotThreatAndRiskSettingsAreValidated(){var p=new RiskPolicy(new MockEnvironment());assertEquals(0,p.assess(false,false,false,false).score());assertEquals("LOW",p.assess(false,false,false,false).severity());assertThrows(IllegalArgumentException.class,()->new RiskPolicy(new MockEnvironment().withProperty("security.threat.risk.high-score","1")));}
 @Test void riskBoundariesAreDeterministicAndConfigurable(){var p=new RiskPolicy(new MockEnvironment().withProperty("security.threat.risk.device-weight","90"));assertEquals("CRITICAL",p.assess(true,false,false,false).severity());assertEquals("MEDIUM",new RiskPolicy(new MockEnvironment()).assess(true,false,false,false).severity());}
 @Test void dockerPrivateVpnAndDocumentationIpsHaveNoLocation(){for(String ip:List.of("172.21.0.1","127.0.0.1","192.168.1.2","100.64.1.1","::1","fc00::1","203.0.113.5","2001:db8::1","hostname.example"))assertFalse(ConfiguredLocationProvider.publicIp(ip),ip);assertTrue(ConfiguredLocationProvider.publicIp("8.8.8.8"));assertTrue(new ConfiguredLocationProvider("").lookup("8.8.8.8").isEmpty());}
 @Test void optionalVerifiedMappingExpiresAndNeverLocatesPrivateIp() throws Exception {
  Path file=temp.resolve("geo.properties");Files.writeString(file,"8.8.8.8=US|TestRegion|"+LocalDate.now(ZoneOffset.UTC)+"|IsolatedTestSource\n172.21.0.1=US|X|"+LocalDate.now(ZoneOffset.UTC)+"|TestSource\n1.1.1.1=AU|Test|2000-01-01|ExpiredSource");
  var p=new ConfiguredLocationProvider(file.toString());assertEquals("US",p.lookup("8.8.8.8").orElseThrow().country());assertTrue(p.lookup("172.21.0.1").isEmpty());assertTrue(p.lookup("1.1.1.1").isEmpty());
 }
}
