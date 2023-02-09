package com.metoo.nspm.core.jwt.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.metoo.nspm.entity.nspm.User;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.crypto.SecureRandomNumberGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;
import java.util.Map;

/**
 * <p>
 * Title: JwtUtil
 * </p>
 *
 * <p>
 * Description: JWT 工具类
 *
 * 常见异常
 *      SignatureVerifcationException：签名不一致异常
 *      TokenExpiredException：令牌过期异常
 *      AlgorithmMismatchException：算法不匹配异常
 *      InvalidClaimException：失效的payload异常
 * </p>
 *
 * <author>
 * HKK
 * </author>
 */
@Slf4j
@Component
public class JwtUtil {

    private Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    private static final String SING = "!WR$%^YGB#$FS";

    // 过期时间5分钟
    private static final long EXPIRE_TIME = 5 * 60 * 1000;

    // 私钥
    public static final String SECRET = "SECRET_VALUE";

    // 请求头
    public static final String AUTH_HEADER = "X-Authorization-With";


    /**
     * 验证token是否正确
     */
    public static boolean verify(String token, String username, String secret) {
        try {
            Algorithm algorithm = Algorithm.HMAC256(secret);
            JWTVerifier verifier = JWT.require(algorithm).withClaim("username", username).build();
            verifier.verify(token);
            return true;
        } catch (JWTVerificationException exception) {
            return false;
        }
    }

    /**
     * 获得token中的自定义信息，无需secret解密也能获得
     */
    public static String getClaimFiled(String token, String filed) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim(filed).asString();
        } catch (JWTDecodeException e) {
            return null;
        }
    }

    /**
     * 生成签名
     */
    public static String sign(String username, String secret) {
        try {
            Date date = new Date(System.currentTimeMillis() + EXPIRE_TIME);
            Algorithm algorithm = Algorithm.HMAC256(secret);
            // 附带username，nickname信息
            return JWT.create().withClaim("username", username).withExpiresAt(date).sign(algorithm);
        } catch (JWTCreationException e) {
            return null;
        }
    }

    /**
     * 获取 token的签发时间
     */
    public static Date getIssuedAt(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getIssuedAt();
        } catch (JWTDecodeException e) {
            return null;
        }
    }

    /**
     * 验证 token是否过期
     */
    public static boolean isTokenExpired(String token) {
        Date now = Calendar.getInstance().getTime();
        DecodedJWT jwt = JWT.decode(token);
        return jwt.getExpiresAt().before(now);
    }

    /**
     * 刷新 token的过期时间
     */
    public static String refreshTokenExpired(String token, String secret) {
        DecodedJWT jwt = JWT.decode(token);
        Map<String, Claim> claims = jwt.getClaims();
        try {
            Date date = new Date(System.currentTimeMillis() + EXPIRE_TIME);
            Algorithm algorithm = Algorithm.HMAC256(secret);
            JWTCreator.Builder builer = JWT.create().withExpiresAt(date);
            for (Map.Entry<String, Claim> entry : claims.entrySet()) {
                builer.withClaim(entry.getKey(), entry.getValue().asString());
            }
            return builer.sign(algorithm);
        } catch (JWTCreationException e) {
            return null;
        }
    }

    /**
     * 生成16位随机盐
     */
    public static String generateSalt() {
        SecureRandomNumberGenerator secureRandom = new SecureRandomNumberGenerator();
        String hex = secureRandom.nextBytes(16).toHex();
        return hex;
    }
    /**
     * 生成token
     *
     * @return
     */
    public static String getToken(Map<String, String> map) {

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, 7);

        // 创建JWT Builder
        JWTCreator.Builder builder = JWT.create();

        // Payload
        map.forEach((k, v) -> {
            builder.withClaim(k, v);
        });
        String token = builder.withExpiresAt(calendar.getTime()).sign(Algorithm.HMAC256(SING));

       /* String token = JWT.create().withHeader(map)
                .withClaim("userId", 10)
                .withClaim("userName", "Hkk")
                .withExpiresAt(calendar.getTime())
                .sign(Algorithm.HMAC256(SING));*/
       log.info("JWT Token：" + token);
        System.out.println("JWTToken: " + token);
        return token;
    }

    public static String getToken(User user) {

        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, 7);

        // 创建JWT Builder
        JWTCreator.Builder builder = JWT.create();

        // Payload
        builder.withClaim("username", user.getUsername()).withClaim("role", user.getRoles());
        String token = builder.withExpiresAt(calendar.getTime()).sign(Algorithm.HMAC256(SING));

       /* String token = JWT.create().withHeader(map)
                .withClaim("userId", 10)
                .withClaim("userName", "Hkk")
                .withExpiresAt(calendar.getTime())
                .sign(Algorithm.HMAC256(SING));*/
        log.info("JWT Token：" + token);
        System.out.println("JWTToken: " + token);
        return token;
    }


    /**
     * 验证token 合法性
     */
    public static DecodedJWT verifyJwt(String token) {

        return JWT.require(Algorithm.HMAC256(SING)).build().verify(token);

        // 创建验证对象

        /*JWTVerifier jwtVerifier =  JWT.require(Algorithm.HMAC256(SING)).build().verify(token);*/

        /*DecodedJWT DeCodeJWT = jwtVerifier.verify("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyTmFtZSI6IkhrayIsImV4cCI6MTYxNzk0NjQxMCwidXNlcklkIjoxMH0.0Dnk4oeHbDHiGbaXMALrfBOMDG7-7JoWK5uic8_2bTU");
        SystemTest.out.println("head: " + DeCodeJWT.getHeader());
        SystemTest.out.println("userId: " + DeCodeJWT.getClaim("userId").asInt());
        SystemTest.out.println("userName: " + DeCodeJWT.getClaim("userName").asString());
        SystemTest.out.println("Signature: " + DeCodeJWT.getSignature());
        SystemTest.out.println("ExpiresAt: " + DeCodeJWT.getExpiresAt());*/
    }

    /**
     * 获取token信息
     *
     * @param token
     * @return
     */
    public static DecodedJWT getDecodedJWT(String token) {
        /*JWTVerifier jwtVerifier =  JWT.require(Algorithm.HMAC256(SING)).build();
        DecodedJWT DeCodeJWT = jwtVerifier.verify(token);*/
        DecodedJWT DeCodeJWT = JWT.require(Algorithm.HMAC256(SING)).build().verify(token);

        return DeCodeJWT;
    }

    public static void main(String[] args) {
        String token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJleHAiOjE2NzY1MzQ0MzksInVzZXJuYW1lIjoiYWRtaW4ifQ.kZYjxV9XcjmunebPd2N_m_ZpMTBaP1zFlFClSiCCC0U";
        String username = JwtUtil.getClaimFiled(token, "username");
        System.out.println(username);
    }
}
