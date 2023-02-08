package com.metoo.nspm.core.redis.util;

import org.springframework.stereotype.Component;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.Transaction;

import java.util.List;

@Component
public class SeckillUtil {

    // 简单模式描述
    // 问题一（并发模式下，库存超出）
    // 问题二（连接超时）
    public boolean kill(String userId, String productId){
        // 1,userId和productId判断
        if (userId == null && productId == null){
            return false;
        }
        // 2,链接Redis或使用Redis工厂获取Redis连接
//        Jedis jedis = new Jedis("127.0.0.1",6379);
        //2 并发模式
        Jedis jedis = JedisPoolUtil.getJedis();

        // 3,拼接key
        // 3.1 库存key
        String productKey = "sk:" + productId + ":qt";
        // 3.2 秒杀成功key
        String userKey = "sk:" + productId + ":us";

        // 监视库存
        jedis.watch(productKey);

        // 4,获取库存，如果库存null，秒杀未开启（后台设置秒杀开启时，设置redis秒杀库存key,关闭时则清除）
        String kc = jedis.get("productKey");
        if(kc == null){
            System.out.println("秒杀未开始，请等待");
            jedis.close();
            return false;
        }
        // 5,判断用户是否重复秒杀操作
        if (jedis.sismember(userKey,userId)){
            System.out.println("已经秒杀成功，不能重复秒杀");
            jedis.close();
            return false;
        }

        // 6, 判断如果商品数量，库存数量（秒杀库存）小于1，秒杀结束
        if (Integer.parseInt(kc) <= 0){
            System.out.println("秒杀已结束");
            jedis.close();
            return false;
        }

        // 7,秒杀过程
        // 开启事务
        Transaction multi = jedis.multi();
        // 开始组队
        multi.decr(productKey);
        multi.sadd(userKey,userId);
        // 开始执行
        List<Object> result = multi.exec();
        if(result == null || result.size() == 0){
            System.out.println("秒杀失败");
            jedis.close();
            return false;
        }


        // 7.1 库存-1
        jedis.decr(productKey);
        // 7.2 把秒杀成功用户添加清单里
        jedis.sadd(userKey,userId);
        System.out.println("秒杀成功");
        jedis.close();
        return true;
    }

    // 并发模式秒杀
    public boolean concurrence(String userId, String productId){

        // 1,userId和productId判断

        // 2,链接Redis或使用Redis工厂获取Redis连接


        // 3,拼接key
        // 3.1 库存key
        String productKey = "sk:" + productId + ":qt";
        // 3.2 秒杀成功key
        String userKey = "sk:" + productId + ":us";

        // 4,获取库存，如果库存null，秒杀未开启（后台设置秒杀开启时，设置redis秒杀库存key,关闭时则清除）

        // 5,判断用户是否重复秒杀操作

        // 6, 判断如果商品数量，库存数量（秒杀库存）小于1，秒杀结束

        // 7,秒杀过程
        // 7.1 库存-1
        // 7.2 把秒杀成功用户添加清单里
        return true;
    }
}
