package com.metoo.nspm.core.utils.logger;

import com.mysql.cj.log.LogFactory;
import org.apache.log4j.BasicConfigurator;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Log4j2Loggers {

    // _slf4j
//    Logger log = LoggerFactory.getLogger(Log4j2Loggers.class);
    // log4j
//    Logger log = LogManager.getLogger(Log4j2Loggers.class);
    // log4j2
    Logger log = LoggerFactory.getLogger(Log4j2Loggers.class);

    @Test
    public void testLog(){
        System.out.println("测试'System.out'打印日志");

        BasicConfigurator.configure();

        log.info("测试日志框架打印日志");
    }

    // 日志拆分

}
