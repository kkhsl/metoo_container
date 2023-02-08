package com.metoo.nspm.core.utils.thread;

import org.jetbrains.annotations.NotNull;
import org.springframework.stereotype.Component;

import java.util.concurrent.*;

/**
 * 构建线程池
 * 参数列表（7）
         int corePoolSize,// 核心线程数
         int maximumPoolSize,// 最大线程数
         long keepAliveTime,// 最大空闲时间
         TimeUnit unit,// 时间单位
         BlockingQueue<Runnable> workQueue,// 阻塞队列
         ThreadFactory threadFactory// 线程工厂
         RejectedExecutionHandler handler// 拒绝策略
 */

@Component
public class ThreadPool {
    ExecutorService fixedThreadPool = Executors.newSingleThreadExecutor();// 创建单线程池
    // 不推荐使用，这种方式对现成的控制粒度比较低
    //ExecutorService fixedThreadPool = Executors.newFixedThreadPool(10);//定长线程池
    // ExecutorService fixedThreadPool = Executors.newCachedThreadPool();//

    public void test(){
        // 推荐手动创建线程池
        ThreadPoolExecutor executor = new ThreadPoolExecutor(
                2,
                4,
                10,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(2),
                new ThreadFactory() {
                    @Override
                    public Thread newThread(@NotNull Runnable r) {
                        Thread t = new Thread(r);
                        t.setName("t1");
                        return t;
                    }
                }, new ThreadPoolExecutor.AbortPolicy());
        // 线程池执行任务
        executor.execute(() ->{
            for (int i = 0; i <= 10; i++){
                System.out.println(i);
            }
        });
    }


    private static ThreadPool pool = new ThreadPool();// 创建单例

    /**
     * 获取一个单例
     * @return
     */
    public static ThreadPool getInstance(){
        return pool;
    }

    public ExecutorService getFixedThreadPool(int size){
        return Executors.newFixedThreadPool(size);
    }

    public void addThread(Runnable run) {
        fixedThreadPool.execute(run);
    }

    /**
     * @description 获取线程池对象
     * @return
     */
    public ExecutorService getService() {
        return fixedThreadPool;
    }

}
