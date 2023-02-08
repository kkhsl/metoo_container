package com.metoo.nspm.core.utils.quartz;

import com.metoo.nspm.core.redis.util.JedisPoolUtil;
import com.metoo.nspm.core.redis.util.JedisUtils;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;
import redis.clients.jedis.JedisPubSub;

/**
 * Redis:键空间通知来实现定时任务
 * 思路：给所有定时任务设置一个过期时间，等到了过期之后，我们通过订阅过期消息就能感知到定时任务执需要执行了，此时我们执行定时任务即可
 */
public class TaskExample {

    public static final String _TOPIC = "__keyevent@0__:expired"; // 订阅频道名称

    public static void main(String[] args) {

//        Jedis jedis = JedisUtils.getJedis();
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
        // 执行定时任务
        doTask(jedis);
    }
    /**
     * 订阅过期消息，执行定时任务
     * @param jedis Redis 客户端
     */
    public static void doTask(Jedis jedis) {
        // 订阅过期消息
        jedis.psubscribe(new JedisPubSub() {
            @Override
            public void onPMessage(String pattern, String channel, String message) {
                // 接收到消息，执行定时任务
                System.out.println("收到消息：" + message);
            }
        }, _TOPIC);
    }
}
