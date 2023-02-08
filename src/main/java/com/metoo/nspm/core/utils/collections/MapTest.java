package com.metoo.nspm.core.utils.collections;

import com.sun.tools.javac.code.Scope;
import org.junit.Test;

import java.util.*;

public class MapTest {

    /**
     * map集合遍历的四种方式
     */
    private static Map map = new HashMap();
//    private static Map map = new LinkedHashMap();

    static {
        map.put("key1", "value1");
        map.put("key2", "value2");
        map.put("key3", "value3");
        map.put("key4", "value4");
        map.put("key5", "value5");
    }


    // 第一种：Keyset
    @Test
    public void keyset(){
        System.out.println(map);
        Set<String> keys = map.keySet();
        for (String key : keys) {
            System.out.println("Key：" + key + " Value：" + map.get(key));
        }
    }


    // 第二种方式 EntrySet
    @Test
    public void entrySet(){
        System.out.println(map);
        Set<Map.Entry<String, String>> entrySet = map.entrySet();
        for(Map.Entry<String, String> entry : entrySet){
            System.out.println("Key：" + entry.getKey() + " Value：" + entry.getValue());
        }
    }

    // 第三种方式：Lambda
    @Test
    public void lambda(){
        System.out.println(map);
        map.forEach((k, v) ->{
            System.out.println("Key：" + k + " Value：" + v);
        });
    }

    // 第四种：iterator:迭代器
    @Test
    public void iterator(){
        Iterator<Map.Entry<String, String>> iterator = map.entrySet().iterator();
        while (iterator.hasNext()){
            Map.Entry<String, String> next = iterator.next();
            System.out.println("Key：" + next.getKey() + " Value：" + next.getValue());
        }
    }


    @Test
    public void circulication(){
        Iterator<Map.Entry<String, String>> iterator = map.entrySet().iterator();
        while(iterator.hasNext()){
            Map.Entry<String, String> next = iterator.next();
            if(next.getKey().equals("key2")){
//                map.remove(next.getKey());  ConcurrentModificationException
//                iterator.remove();
            }
        }
        System.out.println(map);
    }
}
