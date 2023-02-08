package com.metoo.nspm.core.ssh.excutor;

import com.metoo.nspm.core.ssh.utils.DateUtils;
import com.metoo.nspm.core.ssh.utils.IdGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.scheduling.concurrent.ThreadPoolTaskExecutor;

import java.util.Date;
import java.util.HashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executor;

@Configuration
@EnableAsync
public class ThreadPoolExecutorConfig {


    private static Logger logger = LoggerFactory.getLogger(ThreadPoolExecutorConfig.class);

    public static HashMap<String, ExecutorDto> INFO_MAP = new HashMap();
    public static ConcurrentHashMap<String, Thread> RUNNING_MAP = new ConcurrentHashMap();

    public ThreadPoolExecutorConfig() {
    }

    @Bean
    public Executor discoverSshExecutor() {
        ThreadPoolTaskExecutor executor = new ThreadPoolTaskExecutor();
        executor.setCorePoolSize(5);
        executor.setMaxPoolSize(5);
        executor.setKeepAliveSeconds(30);
        executor.setQueueCapacity(200);
        executor.setThreadNamePrefix("discover-ssh-");
        executor.setRejectedExecutionHandler((r, e) -> {
            try {
                String id = DateUtils.formatDate(new Date(), new Object[]{"yyyyMMddHHmmss"}) + "-" + IdGenerator.randomBase62(6);
                logger.warn("任务id：" + id + "，线程池 discoverSshExecutor 已经超出最大线程数，队列阻塞，等待可用空间再继续！目前队列数量：" + e.getQueue().size() + "个，线程信息：" + new Date());
                e.getQueue().put(r);
                logger.warn("任务id：" + id + "，线程池 discoverSshExecutor 阻塞已经解除！");
            } catch (InterruptedException var3) {
                logger.error("线程池 discoverPingExecutor 超出最大线程数：", var3);
            }

        });
        executor.initialize();
        return executor;
    }
}
