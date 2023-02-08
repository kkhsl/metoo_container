package com.metoo.nspm.core.redis.util;

import org.springframework.stereotype.Component;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

/**
 * Jedis
 */
@Component
public class JedisUtils {

    // 服务器地址
    private static String ADDR = "127.0.0.1";
    // 端口
    private static int PORT = 6379;
    // 密码
    private static String AUTH = "123456";

    // 连接实例的最大连接数
    private static int MAX_ACTIVE = 1024;

    // 控制一个pool最多有多少个状态idle（空闲）的jedis实例，默认值为8
    private static int MAX_IDLE = 200;

    // 等待可用连接的最大时间，单位毫秒，默认值为-1，表示永不超时。如果超过等待时间，则直接抛出异常JedisConnectionException
    private static int MAX_WAIT = 10000;

    // 连接超时时间
    private static int TIMEOUT = 10000;

    // 在borrow一个Jedis实例时，是否提前进行validate操作；如果为true，则得到jedis实例均是可用的
    private static boolean TEST_ON_BORROW = true;

    private static JedisPool jedisPool = null;

    // 数据库模式是16个数据库 0~15
    public static final int DEFAULT_DATABASE = 0;

    /**
     * 初始化Redis连接池
     */
    static{
        try {
            JedisPoolConfig jedisPoolConfig = new JedisPoolConfig();
            jedisPoolConfig.setMaxTotal(MAX_ACTIVE);
            jedisPoolConfig.setMaxIdle(MAX_IDLE);
            jedisPoolConfig.setMaxWaitMillis(MAX_WAIT);
            jedisPoolConfig.setTestOnBorrow(TEST_ON_BORROW);
            jedisPool = new JedisPool(jedisPoolConfig, ADDR, PORT, TIMEOUT,AUTH, DEFAULT_DATABASE);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * 获取Jedis实例
     * @return
     */
    public synchronized static Jedis getJedis(){
        try {
            if(jedisPool != null){
                Jedis jedis = jedisPool.getResource();
                System.out.println("redis--服务正在运行：" + jedis.ping());
                return jedis;
            }else{
                JedisPoolConfig jedisPoolConfig = new JedisPoolConfig();
                jedisPoolConfig.setMaxTotal(MAX_ACTIVE);
                jedisPoolConfig.setMaxIdle(MAX_IDLE);
                jedisPoolConfig.setMaxWaitMillis(MAX_WAIT);
                jedisPoolConfig.setTestOnBorrow(TEST_ON_BORROW);
                jedisPool = new JedisPool(jedisPoolConfig, ADDR, PORT, TIMEOUT,AUTH, DEFAULT_DATABASE);
                Jedis jedis = jedisPool.getResource();
                System.out.println("redis--服务正在运行：" + jedis.ping());
                return jedis;
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 释放jedis连接资源
     */
    public static void close(final Jedis jedis){
        if(jedis != null){
            jedis.close();
        }
    }

}
