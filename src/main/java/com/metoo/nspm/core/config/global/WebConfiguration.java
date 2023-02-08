package com.metoo.nspm.core.config.global;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * <p>
 *     Title: WebConfiguration.java
 * </p>
 *
 * <p>
 *     Description: 注册过滤器
 * </p>
 *
 * <p>
 *     实现方式
 *      方式一：在SpringBoor应用启动类添加@ServletComponentScan注解，表示项目启动自动扫描Servlet组件，Filter属于组件
 *      在过滤器方法上增加@WebFilter注解，urlPatterns过滤器要过滤的URL规则配置，filterName过滤器名称
 *      @Order(int) 注解，配合 @WebFilter 注解使用，用于多个过滤器时定义执行顺序，值越小越先执行。
 *      方式二：
 *          自定义配置类加载自定义过滤器 ReqResFilter，
 *          @Configuration
 *          @Bean
 *          FilterRegistrationBean
 *
 *      方式三：
 *          假如我们在项目里引入了第三方的jar，要使用jar里面带的 Filter 的话，如果引用的某个jar包中的过滤器，
 *          且这个过滤器在实现时没有使用 @Component 标识为Spring Bean，则这个过滤器将不会生效。此时需要通过java代码去注册这个过滤器。
 *          也是使用该种方式进行注册
 * </p>
 *
 * @author HKK
 */

@Configuration
public class WebConfiguration {

//    @Bean
//    public LicenseFilter licenseFilter(){
//        return new LicenseFilter();
//    };

//    @Bean
//    public FilterRegistrationBean registerTestFilter(){
//        FilterRegistrationBean  registration = new FilterRegistrationBean ();
//        registration.setFilter(licenseFilter());
//        registration.addUrlPatterns("/admin/*","/nspm/*");// 过滤规则
//        registration.setName("License");
//        registration.setOrder(1);
//        return registration;
//    }

}
