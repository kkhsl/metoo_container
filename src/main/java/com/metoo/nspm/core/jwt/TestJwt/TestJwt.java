package com.metoo.nspm.core.jwt.TestJwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.junit.Test;

import java.util.Calendar;
import java.util.HashMap;

/**
 * <p>
 *     Title: TestJwt.java
 * </p>
 *
 * <p>
 *     Description: jwt测试类
 * </p>
 *
 * <author>
 *     HKK
 * </author>
 */
public class TestJwt {

    @Test
    public void jwt(){
        HashMap map = new HashMap();
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.SECOND, 20);
        System.out.println(calendar.getTime());

        String token = JWT.create().withHeader(map)
                    .withClaim("userId", 10)
                    .withClaim("userName","Hkk")
                    .withExpiresAt(calendar.getTime())
                    .sign(Algorithm.HMAC256("QWERT"));
        System.out.println("JWTToken: " + token);
    }

    @Test
    public void testJwt(){
        // 创建验证对象
        JWTVerifier jwtVerifier =  JWT.require(Algorithm.HMAC256("QWERT")).build();

        DecodedJWT DeCodeJWT = jwtVerifier.verify("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyTmFtZSI6IkhrayIsImV4cCI6MTYxNzk0NjQxMCwidXNlcklkIjoxMH0.0Dnk4oeHbDHiGbaXMALrfBOMDG7-7JoWK5uic8_2bTU");
        System.out.println("head: " + DeCodeJWT.getHeader());
        System.out.println("userId: " + DeCodeJWT.getClaim("userId").asInt());
        System.out.println("userName: " + DeCodeJWT.getClaim("userName").asString());
        System.out.println("Signature: " + DeCodeJWT.getSignature());
        System.out.println("ExpiresAt: " + DeCodeJWT.getExpiresAt());


    }
}
