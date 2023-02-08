package com.metoo.nspm.core.config.quartz;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.TaskScheduler;
import org.springframework.scheduling.concurrent.ThreadPoolTaskScheduler;


/**
 *
 * 注意事项：
 *  1：@Scheduled 多个任务使用了该方法，也是一个执行完执行下一个，并非并行执行；原因是scheduled默认线程数为1；
 *  2：每个定时任务才能执行下一次，禁止异步执行（@EnableAsync）
 *  3：并发执行（并行、串行），注意第“1”项里说明的，任务未执行完毕，另一个线程又来执行（是否会等待任务执行完毕，在执行下一次）
 *
 */
//@EnableScheduling
@Configuration
public class SchedulingConfiguration {

    /**
     *任务调度线程池配置
     */
    @Bean
    public TaskScheduler taskScheduler() {
        ThreadPoolTaskScheduler taskScheduler = new ThreadPoolTaskScheduler();
        taskScheduler.setPoolSize(10);
        return taskScheduler;
    }

//    @Bean(destroyMethod="shutdown")
//    public Executor taskExecutor() {
//        return Executors.newScheduledThreadPool(10); //指定Scheduled线程池大小
//    }

    /**
     * 异步任务执行线程池
     * @return
     */
//    @Bean(name = "asyncExecutor")
//    public ThreadPoolTaskExecutor asyncExecutor() {
//        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
//        executor.setCorePoolSize(10);
//        executor.setQueueCapacity(1000);
//        executor.setKeepAliveSeconds(600);
//        executor.setMaxPoolSize(20);
//        executor.setThreadNamePrefix("taskExecutor-");
//        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.CallerRunsPolicy());
//        executor.initialize();
//        return executor;
//    }

}
