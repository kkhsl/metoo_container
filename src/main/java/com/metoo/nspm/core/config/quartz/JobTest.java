//package com.metoo.nspm.core.config.quartz;
//
//import org.springframework.scheduling.annotation.Scheduled;
//import org.springframework.stereotype.Component;
//
//@Component
//public class JobTest {
//
////    @Async
//    @Scheduled(cron = "*/3 * * * * ?")
//    public void w() throws InterruptedException {
//        Long time=System.currentTimeMillis();
//        System.out.println(Thread.currentThread().getId() + "任1务开始");
//        System.out.println("===任务执行耗时："+(System.currentTimeMillis()-time)+"===");
//
//    }
//
//    //    @Async
//    @Scheduled(cron = "*/3 * * * * ?")
//    public void ee() throws InterruptedException {
//        Long time=System.currentTimeMillis();
//        Thread.sleep(10000);
//        System.out.println(Thread.currentThread().getId() + "任2务开始");
//        System.out.println("===任务执行耗时："+(System.currentTimeMillis()-time)+"===");
//
//    }
//
//    //    @Async
//    @Scheduled(cron = "*/3 * * * * ?")
//    public void eee() throws InterruptedException {
//        Long time=System.currentTimeMillis();
//        System.out.println(Thread.currentThread().getId() + "任3务开始");
//        System.out.println("===任务执行耗时："+(System.currentTimeMillis()-time)+"===");
//    }
//
//}
