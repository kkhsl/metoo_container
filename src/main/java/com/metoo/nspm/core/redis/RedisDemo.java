package com.metoo.nspm.core.redis;


import org.junit.Test;
import redis.clients.jedis.Jedis;

import java.util.List;
import java.util.Set;

public class RedisDemo {

    public static void main(String[] args) {
        Jedis jedis = new Jedis();
        jedis.auth("123456");

    }

    @Test
    public void pingPong(){
        Jedis jedis = new Jedis("127.0.0.1",6379);
        jedis.auth("123456");
        String value = jedis.ping();
        System.out.println(value);
    }

    @Test
    public void string(){
        Jedis jedis = new Jedis("127.0.0.1",6379);
        jedis.auth("123456");
        jedis.select(2);

        // 设置单个数据
//        jedis.set("javaKey","javaValue");
        // 获取
        String javaValue = jedis.get("javaKey");
        System.out.println(javaValue);

        // 设置多个数据
        jedis.mset("javaKay1","javaValue1","javaKey2","javaKey3");
        List<String> mget = jedis.mget("javaKey1","javaKey2");

        Set<String> keys = jedis.keys("*");
        for (String key : keys) {
            System.out.println(key);
        }
    }

    @Test
    public void list(){
        // 创建Jedis对象链接
        Jedis jedis = new Jedis("127.0.0.1",6379);
        jedis.auth("123456");
        jedis.select(2);
        jedis.lpush("javaListKey1","javaListValue1","javaListValue2");
        List<String> values = jedis.lrange("javaListKey1",0,-1);
        for (String value : values) {
            System.out.println(value);
        }
    }

    @Test
    public void set(){
        Jedis jedis = new Jedis("127.0.0.1",6379);
        jedis.auth("123456");
        jedis.select(2);

        // 设置单个数据
        jedis.sadd("javaSetKey","javaSetValue1", "javaSetValue2");
        Set<String> set = jedis.smembers("javaSetKey");
        System.out.println(set);
    }

    @Test
    public void hash(){
        Jedis jedis = new Jedis("127.0.0.1",6379);
        jedis.auth("123456");
        jedis.select(2);
        jedis.hset("javaHash","javaHashKey", "javaHashValue");
        String hget = jedis.hget("javaHash","javaHashKey");
        System.out.println(hget);
    }

    @Test
    public void zset(){
        Jedis jedis = new Jedis("127.0.0.1",6379);
        jedis.auth("123456");
        jedis.select(2);
        jedis.zadd("javaZsetKey",100d,"javaZsetValue1");
        jedis.zadd("javaZsetKey",100d,"javaZsetValue2");

        Set<String> zset = jedis.zrange("javaZsetKey",0,-1);
        System.out.println(zset);
        Long index = jedis.zrank("javaZsetKey","javaZsetValue2");
        System.out.println(index);
    }
}
