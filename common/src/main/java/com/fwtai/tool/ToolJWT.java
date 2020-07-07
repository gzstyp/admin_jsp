package com.fwtai.tool;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.io.Serializable;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * jwt(JSON Web Token)令牌工具类,非对称作为密钥
 * @作者 田应平
 * @版本 v1.0
 * @创建时间 2020-02-12 23:53
 * @QQ号码 444141300
 * @Email service@yinlz.com
 * @官网 <url>http://www.yinlz.com</url>
*/
public final class ToolJWT implements Serializable{

    //如设置Token过期时间15分钟，建议更换时间设置为Token前5分钟,通过try catch 获取过期
    private final static long accessToken = 1000 * 60 * 45;//当 refreshToken 已过期了，再判断 accessToken 是否已过期,

    /**一般更换新的access_token小于5分钟则提示需要更换新的access_token*/
    private final static long refreshToken = 1000 * 60 * 40;//仅做token的是否需要更换新的accessToken标识,小于5分钟则提示需要更换新的accessToken

    private final static String issuer = "贵州富翁泰科技有限责任公司";//jwt签发者

    /**2048的密钥位的公钥*/
    private final static String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCGux/yERhRjyt2Y7gJa3qWFoEbNVVuF8KVYUFPmwK8udhor67VkCKiPRktQkudjaqwX/HXj2isiRDT2F7HLcABBu7/74vUQ0xzDCbo5ETLXLNWP5SpftOnkqeXSrPpOYhg75eSFS21QkkBnWqJK2EjkkBUUKQKuusXpBYtP9h6+wIDAQAB";
    /**2048的密钥位的私钥*/
    private final static String privateKey = "MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAIa7H/IRGFGPK3ZjuAlrepYWgRs1VW4XwpVhQU+bAry52GivrtWQIqI9GS1CS52NqrBf8dePaKyJENPYXsctwAEG7v/vi9RDTHMMJujkRMtcs1Y/lKl+06eSp5dKs+k5iGDvl5IVLbVCSQGdaokrYSOSQFRQpAq66xekFi0/2Hr7AgMBAAECgYADGRxz8YawoW0rbMGXndwUxXG0kXZkcLFtw+2/id33PwLF7XxEturE9ki07LhWaCKLqbki7s5GYWR8qpYLWHb4xnVxuZMtH/KD198tZz77zh35qdmOzhOirPudoKua7vhDZFb5EUjx4AYSffI47PuzAyWqTWxyyoVr/0H6MKhNmQJBANPpQcp5CS8iFXkuYookH5t2qNEr7yGg31KbtQA82f0Ky4gCJj23fS5Xjf5BESV0DGoKrL6oi+4zqq7vp0QK9u0CQQCiwx74PlT+0pOHPvnLXigV3x088C0XTiyKZtUpeFDhPB7mauIzMQ2dYU+a9rLDvS/QnAMeADceOEWZ7rqJZNSHAkEAsBWd9pmWeRTQVQ6nEPStUuhJpO3l2cKsbx81SspFtM8Yip6GmjfzC+Py+DenAMEqY58VJaQ2Civig1ReX9rgjQJAP+LOuSneOtd0yNVTPxwKJ+uXkl/Dky5AFWMfsFNli8MJbe/uMaHDck7L7EuBB4uuxPc30gLLn7T+vNkTpvJI6QJAcJosBLHGLyn+41VBJQrXluXArv/wnJFlXeScCA2ID5B3HJ8+l9KTt+wyLvt1WXL6CbJQIwji/iYGJ3wEZsLddA==";

    /**java生成的私钥是pkcs8格式的公钥是x.509格式*/
    private final static PublicKey getPublicKey(){
        try {
            final byte[] keyBytes = Base64.getDecoder().decode(publicKey);
            final X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            final PublicKey publicKey = keyFactory.generatePublic(keySpec);
            return publicKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private final static PrivateKey getPrivateKey(){
        try {
            final byte[] keyBytes = Base64.getDecoder().decode(privateKey);
            final PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
            final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            final PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
            return privateKey;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // setSubject 不能和s etClaims() 同时使用,如果用不到 userId() 的话可以把setId的值设为 userName !!!
    private final static String createToken(final String userId,final Object value,final long expiryDate){
        final ExecutorService threadPool = Executors.newCachedThreadPool();
        final Future<String> future = threadPool.submit(new Callable<String>(){
            @Override
            public String call() throws Exception{
                final Date date = new Date();
                final JwtBuilder builder = Jwts.builder().setIssuer(issuer).signWith(SignatureAlgorithm.RS384,getPrivateKey()).setId(userId).setIssuedAt(date).claim(userId,value).setExpiration(new Date(date.getTime() + expiryDate));
                return builder.compact();
            }
        });
        try {
            return future.get();
        } catch (Exception e) {
            threadPool.shutdown();
            return null;
        }
    }

    public final static Claims parser(final String token){
        return Jwts.parser().requireIssuer(issuer).setSigningKey(getPublicKey()).parseClaimsJws(token).getBody();
    }

    /**
     * 验证token是否已失效,返回true已失效,否则有效
     * @param token
     * @作者 田应平
     * @QQ 444141300
     * @创建时间 2020年2月24日 16:19:00
    */
    public final static boolean tokenExpired(final String token) {
        try {
            return parser(token).getExpiration().before(new Date());
        } catch (final ExpiredJwtException exp) {
            return true;
        }
    }

    /**仅作为是否需要刷新的access_token标识,不做任何业务处理*/
    public final static String expireRefreshToken(final String userId){
        return createToken(userId,null,refreshToken);
    }

    /**生成带认证实体且有权限的token,最后个参数是含List<String>的角色信息,*/
    public final static String expireAccessToken(final String userId,final Object value){
        return createToken(userId,value,accessToken);
    }
}