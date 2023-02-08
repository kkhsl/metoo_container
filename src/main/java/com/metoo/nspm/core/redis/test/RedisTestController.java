package com.metoo.nspm.core.redis.test;

import org.apache.ibatis.annotations.Delete;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequestMapping("/admin/redis")
@RestController
public class RedisTestController {

    @Autowired
    private RedisTemplate redisTemplate;

    @GetMapping("/get")
    public Object get(){
        redisTemplate.opsForValue().set("web_key","web_value");
        Object key = redisTemplate.opsForValue().get("web_key");
        return key;
    }

    @DeleteMapping("/del")
    public void del(){
        redisTemplate.delete("web_key");
    }
}
