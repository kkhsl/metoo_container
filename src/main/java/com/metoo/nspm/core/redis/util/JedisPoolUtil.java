package com.metoo.nspm.core.redis.util;

import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

/**
 * Jedis连接池
 */
public class JedisPoolUtil {


    private static volatile JedisPool jedisPool = null;

    private JedisPoolUtil(JedisPoolConfig config, String s, int i, int i1){

    }

    public static Jedis getJedis(){
        if (jedisPool != null) {
            return jedisPool.getResource();
        }
        return null;
    }

    /**
     * 构建redis连接池
     *
     * @param
     * @param
     * @return JedisPoolUtil
     */
    public static JedisPool getPoolInstance() {
        if (jedisPool == null) {
            synchronized (JedisPoolUtil.class){
                JedisPoolConfig config = new JedisPoolConfig();
                //控制一个pool可分配多少个jedis实例，通过pool.getResource()来获取；
                //如果赋值为-1，则表示不限制；如果pool已经分配了maxActive个jedis实例，则此时pool的状态为exhausted(耗尽)。
                config.setMaxTotal(200);
                //控制一个pool最多有多少个状态为idle(空闲的)的jedis实例。
                config.setMaxIdle(32);
                //表示当borrow(引入)一个jedis实例时，最大的等待时间，如果超过等待时间，则直接抛出JedisConnectionException；
                config.setMaxWaitMillis(1000 * 100);
                //在borrow一个jedis实例时，是否提前进行validate操作；如果为true，则得到的jedis实例均是可用的；
                config.setTestOnBorrow(true); // ping pong
                jedisPool = new JedisPool(config, "127.0.0.1", 6379,60000);
            }
        }
        return jedisPool;
    }

    /**
     * 返还到连接池
     *
     * @param redis
     * @param redis
     */
    public static void returnResource(JedisPoolUtil jedisPool, Jedis redis) {
        if (redis != null) {
        }
    }

    /**
     * 获取数据
     *
     * @param key
     * @return
     */
//    public static String get(String key){
//        String value = null;
//
//        JedisPoolUtil redis = null;
//        Jedis jedis = null;
//        try {
//            redis = getPoolInstance();
//            jedis = redis.getResource();
//            value = jedis.get(key);
//        } catch (Exception e) {
//            //释放redis对象
//            redis.returnBrokenResource(jedis);
//            e.printStackTrace();
//        } finally {
//            //返还到连接池
//            returnResource(redis, jedis);
//        }
//
//        return value;
//    }
}
