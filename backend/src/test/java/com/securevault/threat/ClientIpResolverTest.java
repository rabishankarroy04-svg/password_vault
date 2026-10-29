package com.securevault.threat;
import com.securevault.common.ClientIpResolver;import org.junit.jupiter.api.Test;import org.springframework.mock.web.MockHttpServletRequest;import static org.junit.jupiter.api.Assertions.*;
class ClientIpResolverTest {
 @Test void untrustedForwardedHeaderCannotChangeClient(){var r=new MockHttpServletRequest();r.setRemoteAddr("172.21.0.1");r.addHeader("X-Forwarded-For","8.8.8.8");assertEquals("172.21.0.1",new ClientIpResolver("").resolve(r));}
 @Test void trustedProxyChainStopsAtFirstUntrustedHop(){var r=new MockHttpServletRequest();r.setRemoteAddr("172.21.0.1");r.addHeader("X-Forwarded-For","9.9.9.9, 8.8.8.8");assertEquals("8.8.8.8",new ClientIpResolver("172.21.0.0/16").resolve(r));}
 @Test void malformedChainIsRejectedAsAWhole(){var r=new MockHttpServletRequest();r.setRemoteAddr("172.21.0.1");r.addHeader("X-Forwarded-For","spoofed, 8.8.8.8");assertEquals("172.21.0.1",new ClientIpResolver("172.21.0.0/16").resolve(r));}
}
