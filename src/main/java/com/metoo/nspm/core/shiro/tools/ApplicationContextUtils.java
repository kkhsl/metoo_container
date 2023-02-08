package com.metoo.nspm.core.shiro.tools;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.stereotype.Component;

/**
 *<p>
 *     Title: ApplicationContextUtils
 *</p>
 *
 * <p>
 *     Description: 通过ApplicationContextUtils 工厂类，根据bean 的名称获取指定bean对象
 * </p>
 *
 * <author>
 *  HKK
 * </author>
 */
@Component
public class ApplicationContextUtils implements ApplicationContextAware {

    private static ApplicationContext applicationContext;

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        if(ApplicationContextUtils.applicationContext == null) {
            ApplicationContextUtils.applicationContext = applicationContext;
        }
    }

    /**
     * 获取applicationContext
     */
    public static ApplicationContext getApplicationContext() {
        return applicationContext;
    }


    // 通过bean名称获取工厂中指定bean对象
    public static Object getBean(String beanName){
        return applicationContext.getBean(beanName);
    }
}
