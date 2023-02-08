package com.metoo.nspm.core.shiro.cache;

import com.metoo.nspm.core.shiro.tools.ApplicationContextUtils;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.StringRedisSerializer;

import java.util.Collection;
import java.util.Set;

/**
 * <p>
 *     Title: RedisCache.java
 * </p>
 *
 * <p>
 *  Description: 自定义redis缓存实现
 * </p>
 */
public class RedisCache<k,v> implements Cache<k,v> {

    private String cacheName;

    public RedisCache() {
    }

    public RedisCache(String cacheName) {
        this.cacheName = cacheName;
    }

    @Override
    public v get(k k) throws CacheException {
        System.out.println("get key : " + k);

        // 第一种
        //return (v) getRedisTemplate().opsForValue().get(k.toString());

        // 第二种
        return (v) getRedisTemplate().opsForHash().get(this.cacheName, k.toString());
    }

    @Override
    public v put(k k, v v) throws CacheException {
        System.out.println("put key : " + k);
        System.out.println("put v " + v);
        // 第一种
        //getRedisTemplate().opsForValue().set(k.toString(), v);
        // 第二种
        getRedisTemplate().opsForHash().put(this.cacheName, k.toString(), v);
        return null;
    }

    @Override
    public v remove(k k) throws CacheException {

        return (v) getRedisTemplate().opsForHash().delete(this.cacheName, k.toString());
    }

    @Override
    public void clear() throws CacheException {
        getRedisTemplate().delete(this.cacheName);
    }

    @Override
    public int size() {
        return getRedisTemplate().opsForHash().size(this.cacheName).intValue();
    }

    @Override
    public Set<k> keys() {
        return getRedisTemplate().opsForHash().keys(this.cacheName);
    }

    @Override
    public Collection<v> values() {
        return getRedisTemplate().opsForHash().values(this.cacheName);
    }


    private RedisTemplate getRedisTemplate(){
        RedisTemplate redisTeplemplate = (RedisTemplate) ApplicationContextUtils.getBean("redisTemplate");
        //
        redisTeplemplate.setKeySerializer(new StringRedisSerializer());
        //
        redisTeplemplate.setHashKeySerializer(new StringRedisSerializer());

        return redisTeplemplate;
    }
}
