package com.metoo.nspm.core.utils.quartz;

import java.util.Date;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * ScheduledExecutorService：Java（JDK1.5）自带的定时任务类（java.util.*）
 * 优点：实现了Timer所有功能，并解决了Timer类存在的问题
 * 缺点：该方案仅适用于单机环境
 */
public class MyScheduledExecutorService {

    public static void main(String[] args) {
        // 创建任务队列 10为线程数量
        ScheduledExecutorService scheduledExecutorService = Executors.newScheduledThreadPool(10);
        // 执行任务
        scheduledExecutorService.scheduleAtFixedRate(() ->{
            System.out.println("打印当前时间：" + new Date());
        },1, 3, TimeUnit.SECONDS);// 1s后开始执行，每3s执行一次
    }
}
