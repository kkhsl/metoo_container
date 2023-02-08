package com.metoo.nspm.core.config.aop;

import com.metoo.nspm.core.manager.myzabbix.utils.ZabbixApiUtil;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.springframework.stereotype.Component;

/**
 *
 */

@Aspect
@Component
public class ZabbixAop {

    //切点
    @Pointcut("execution(* com.metoo.nspm.core.service.api.zabbix..*.*(..))")
    private void cutMethod() {
    }

//    @Around("cutMethod()")
    public Object isAvailability(ProceedingJoinPoint joinPoint) throws Throwable {

        // 校验Api是否可用
        ZabbixApiUtil.verifyZabbix();
        if(ZabbixApiUtil.ZABBIX_API != null){
            return joinPoint.proceed();
        }else{
            return null;
        }
    }

}
