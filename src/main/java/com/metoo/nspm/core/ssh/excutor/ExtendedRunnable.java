package com.metoo.nspm.core.ssh.excutor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

public abstract class ExtendedRunnable implements Runnable {

    private static final Logger logger = LoggerFactory.getLogger(ExtendedRunnable.class);
    private ExecutorDto executorDto;

    protected abstract void start() throws InterruptedException, Exception;

    public ExtendedRunnable(ExecutorDto executorDto) {
        this.executorDto = executorDto;
    }

    public ExecutorDto getExecutorDto() {
        return this.executorDto;
    }

    public void setExecutorDto(ExecutorDto executorDto) {
        this.executorDto = executorDto;
    }

    public void run() {
        if (StringUtils.isEmpty(this.executorDto.getId())) {
            try {
                throw new Exception("请命名启动线程的id！");
            } catch (Exception var8) {
                logger.error("线程Id为空", var8);
            }
        } else if (ThreadPoolExecutorConfig.RUNNING_MAP.containsKey(this.executorDto.getId()) && ThreadPoolExecutorConfig.INFO_MAP.containsKey(this.executorDto.getId())) {
            try {
                throw new Exception("请勿重复提交相同的线程id！");
            } catch (Exception var9) {
                logger.error("线程Id重复", var9);
            }
        } else {
            try {
                this.beforeExecute(this.executorDto, Thread.currentThread());
                this.start();
            } catch (InterruptedException var10) {
                logger.error("线程InterruptedException:" + this.executorDto.toString(), var10);
            } catch (Exception var11) {
                logger.error("线程未知Exception:" + this.executorDto.toString(), var11);
            } finally {
                this.afterExecute(this.executorDto);
            }

        }
    }

    protected void beforeExecute(ExecutorDto dto, Thread t) {
        ThreadPoolExecutorConfig.RUNNING_MAP.put(dto.getId(), t);
        ThreadPoolExecutorConfig.INFO_MAP.put(dto.getId(), dto);
        logger.debug("beforeExecute>> RUNING_MAP.size():" + ThreadPoolExecutorConfig.RUNNING_MAP.size() + ", INFO_MAP.size():" + ThreadPoolExecutorConfig.INFO_MAP.size() + ", 线程info" + dto.toString());
    }

    protected void afterExecute(ExecutorDto dto) {
        ThreadPoolExecutorConfig.RUNNING_MAP.remove(dto.getId());
        ThreadPoolExecutorConfig.INFO_MAP.remove(dto.getId());
        logger.debug("afterExecute>> RUNING_MAP.size():" + ThreadPoolExecutorConfig.RUNNING_MAP.size() + ", INFO_MAP.size():" + ThreadPoolExecutorConfig.INFO_MAP.size() + ", 线程info" + dto.toString());
    }
}
