package com.metoo.nspm.core.manager.admin.action;

import com.metoo.nspm.core.service.nspm.IRackService;
import com.metoo.nspm.core.service.nspm.TestInitService;
import com.metoo.nspm.entity.nspm.Rack;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

@RestController
public class TestInitAction {

    @Autowired
    private TestInitService testInitService;
    @Autowired
    private IRackService rackService;

    private static Long domainId = 0L;

    @Value("asd")
    private String client;

    private String b;

    public void init(){
        this.b="456";
    }

    public static void main(String[] args) {
//        System.out.println(System.getenv());

        try {
            testThreadPool();
//            testThread();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    @RequestMapping("/admin/testInit")
    public String test(){
        System.out.println(client);
        System.out.println(b);
        return this.testInitService.getA();
    }

    @RequestMapping("testadd")
    public void testAdd(){
        Map params = new HashMap();
        params.put("orderBy", "addTime");
        params.put("orderType","desc");
        List<Rack> racks = this.rackService.selectObjByMap(params);
        if(racks.size() > 0){
            Rack rack = racks.get(0);
            if(rack.getId() != domainId && rack.getId() > domainId){
                domainId = rack.getId();
                System.out.println(domainId);
                // 更新路由数据
            }
        }
    }

    public static int testThread() throws InterruptedException {
        int n = 10;
        for (int i = 1; i <= n; i++ ){

            System.out.println(Thread.currentThread().getName());
            Thread.sleep(1000);
        }
        return n;
    }

    public static int testThreadPool() throws InterruptedException {
        Long begin = System.currentTimeMillis();
        int n = 1000;
        ExecutorService exe = Executors.newFixedThreadPool(1000);;
        for (int i = 1; i <= n; i++ ){
            int finalI = i;
            exe.execute(new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        Thread.sleep(3000);
                        System.out.println(Thread.currentThread().getName());
                        System.out.println("pool:" + finalI);
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }}));

        }
        if(exe != null){
            exe.shutdown();
        }
        while (true) {
            if (exe == null || exe.isTerminated()) {
                Long end = System.currentTimeMillis();
                System.out.println(end - begin);
                return n;

            }
        }
    }


}
