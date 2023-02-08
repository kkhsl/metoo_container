package com.metoo.nspm.core.config.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD,ElementType.FIELD,ElementType.CONSTRUCTOR})
@Retention(RetentionPolicy.RUNTIME)
public @interface OperationLogAnno {

    /**
     * 操作位置
     */
    String operatePage() default "";
    /**
     * 操作类型
     */
    String operateType() default "";
    /**
     * 业务域,各自业务自己定义
     */
    String bizType() default "";
    /**
     * 操作类型(枚举类型)
     */
    OperationType operationType() default OperationType.OTHER;

    String name() default "";
}
