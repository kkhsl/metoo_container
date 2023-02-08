package com.metoo.nspm.core.config.listerner;

import com.metoo.nspm.core.service.nspm.ILicenseService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.annotation.WebListener;

/**
 * 系统基础监听器， 用来生成sn申请码；该监听器会在系统启动时进行数据加载；
 *  容器初始化时调用contextInitialized（）方法
 *
 *
 */
@WebListener
public class MyListnerter implements ServletContextListener {

    private static WebApplicationContext context;

    private static Logger log = LoggerFactory.getLogger(ServletContextListener.class);

    @Override
    public void contextInitialized(ServletContextEvent servletContextEvent) {
        context = WebApplicationContextUtils.getWebApplicationContext(servletContextEvent.getServletContext());
        ILicenseService licenseService = (ILicenseService)context.getBean("licenseServiceImpl");
//        licenseService.detection();
    }



    @Override
    public void contextDestroyed(ServletContextEvent servletContextEvent) {
        log.info("=========销毁=========");
    }
}
