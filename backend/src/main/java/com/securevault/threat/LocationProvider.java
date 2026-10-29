package com.securevault.threat;
import java.util.Optional;
public interface LocationProvider {
 record Location(String country,String region,String source){}
 Optional<Location> lookup(String ip);
}
