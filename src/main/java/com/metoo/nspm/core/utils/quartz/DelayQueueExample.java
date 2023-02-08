package com.metoo.nspm.core.utils.quartz;

import com.metoo.nspm.core.redis.util.JedisPoolUtil;
import com.metoo.nspm.core.redis.util.JedisUtils;
import org.junit.Test;
import org.springframework.stereotype.Component;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

import java.time.Instant;
import java.util.Set;

/**
 *分布式定时任务
 *
 * 思路：通过ZSET实现定时任务思路，将定时任务存放到ZSET集合，并将过期时间存储到ZSET的score字段中，
 * 然后通过一个无线循环来判断当前时间内是否有需要执行的定时任务，如果有则执行
 *
 */
@Component
public class DelayQueueExample {

    private static final String _KEY = "DelayQueueExample";

    public static void main(String[] args) throws InterruptedException {
//        Jedis jedis = JedisUtils.getJedis();
//        Jedis jedis = JedisPoolUtil.getJedis();
        JedisPool jedisPool = null;
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
        Jedis jedis = jedisPool.getResource();
        if(jedis != null){
            // 30s 后执行
            long delayTime = Instant.now().plusSeconds(30).getEpochSecond();
            jedis.zadd(_KEY, delayTime, "order_1");
            // 继续添加测试数据
            jedis.zadd(_KEY, Instant.now().plusSeconds(20).getEpochSecond(), "order_2");
            jedis.zadd(_KEY, Instant.now().plusSeconds(20).getEpochSecond(), "order_3");
            jedis.zadd(_KEY, Instant.now().plusSeconds(7).getEpochSecond(), "order_4");
            jedis.zadd(_KEY, Instant.now().plusSeconds(10).getEpochSecond(), "order_5");
            // 开启定时任务队列
            doDelayQueue(jedis);
        }
    }
    /**
     * 定时任务队列消费
     * @param jedis Redis 客户端
     */
    public static void doDelayQueue(Jedis jedis) throws InterruptedException {
        while (true) {
            // 当前时间
            Instant nowInstant = Instant.now();
            long lastSecond = nowInstant.plusSeconds(-1).getEpochSecond();
            // 上一秒时间
            long nowSecond = nowInstant.getEpochSecond();
            // 查询当前时间的所有任务
            Set<String> data = jedis.zrangeByScore(_KEY, lastSecond, nowSecond);
            for (String item : data) {
                // 消费任务
                System.out.println("消费：" + item);
            }
            // 删除已经执行的任务
            jedis.zremrangeByScore(_KEY, lastSecond, nowSecond);
            Thread.sleep(1000); // 每秒查询一次
            System.out.println("定时任务正在执行中...");
        }
    }

    @Test
    public void test(){
        Instant nowInstant = Instant.now();
        long lastSecond = nowInstant.plusSeconds(-1).getEpochSecond();
        // 上一秒时间
        long nowSecond = nowInstant.getEpochSecond();

        System.out.println(lastSecond);
        System.out.println(nowSecond);
    }
}
