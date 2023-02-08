package com.metoo.nspm.core.shiro.cache;

import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheException;
import org.apache.shiro.cache.CacheManager;

/**
 * <p>
 *     Title: RedisCacheManager.java
 * </p>
 *
 * <p>
 *     Description: 自定义Redis缓存管理器
 * </p>
 * @author hkk
 */
public class RedisCacheManager implements CacheManager {

    // 参数：1.认证或者是授权缓存的统一名称
    @Override
    public <K, V> Cache<K, V> getCache(String cacheName) throws CacheException {
        System.out.println("cacheName: " + cacheName);
        return new RedisCache<K,V>(cacheName);
    }
}
