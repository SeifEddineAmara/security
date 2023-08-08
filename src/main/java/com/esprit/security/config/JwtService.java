package com.esprit.security.config;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.hibernate.annotations.DialectOverride;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String SECRET_KEY ="jShGbwqTzzt69QxkEOVEAZ640OfHEC2XmZvC+p9zRL0HS66c6VuInGaq9jfYqsQjO5dHwQ/9OD0xzkOpUCa/TfRfZLYJw+0/bC1p6HIUlJCXm09f89a7/P6FZg/1ztNv56EOydWUSjtfW5l0snx/Sv7RFPOEqwFNAKEbsson+BYEL7a2ynTZTGyDMLpmgxdyfCCiWlb5DQFLvxnm3e+Ot0opd7YEBSWtxIJA1F5kE9isbWfebBHrh+sWFF+TEwXDxAD/d3YCjb1QQc5y73pDqepRiox97I/uLn82odNNxsQkOvgrhmspQVGhm7ebv+Q+gh0DaQMIkrUVvZuENkFAMHo/SZX+a9xc+Q1kkVC729A=\n";
    public String extractUsername(String token) {
        return extractClaim(token,Claims::getSubject);
    }

    public <T> T extractClaim(String token, Function<Claims,T> claimsResolver){

        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);

    }

    public String generateToken(UserDetails userDetails){
        return  generateToken(new HashMap<>(),userDetails);
    }

    public boolean isTokenValid(String token, UserDetails userDetails){
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && ! isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {

        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {

        return extractClaim(token,Claims::getExpiration);
    }

    public String generateToken(
    Map<String,Object> extraClaims,
    UserDetails userDetails
            ){
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+ 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }


    private Claims extractAllClaims(String token){

        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);

        return Keys.hmacShaKeyFor(keyBytes);
    }

}
