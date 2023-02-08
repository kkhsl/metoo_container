package com.metoo.nspm;
//
//import DataSourceConfig;
//import NspmDataSourceConfig;
//import TopologyDataSourceConfig;
import com.metoo.nspm.core.service.nspm.ITopologyTokenService;
import com.metoo.nspm.core.service.nspm.TestInitService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.servlet.ServletComponentScan;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;
import org.springframework.core.annotation.Order;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.stereotype.Component;

/**
 * <p>
 *     Title: SpringbootShiroApplication.java
 * </p>
 *
 * <p>
 *     Description: Springboot启动类，springBoot整合Mybatis、Shiro
 *     SpringBoot项目启动时初始化操作的几种方式
 *      第一种：@PostConstruct
 *      第二种：实现 @CommandLineRunner 接口并重写run()方法
 *      第三种：实现 @ApplicationRunner 接口并重写run()方法
 *      第四种：实现org.springframework.beans.factory.InitializingBean接口并重写 afterPropertiesSet()方法
 *
 *
 */


// 等价：<context:component-scan base-package="com.metoo" /> 组件扫描
// @EnableAspectJAutoProxy(proxyTargetClass = true)
//@EnableTransactionManagement// 事务
//@SpringBootApplication(exclude = {NspmDataSourceConfig.class, DataSourceConfig.class, TopologyDataSourceConfig.class}) // 申明让spring boot自动给程序进行必要的配置 == @Configuration ，@EnableAutoConfiguration 和 @ComponentScan
//@MapperScan
@EnableScheduling // 开启定时任务（启动类增加该注解，使项目启动后执行定时任务）
@ServletComponentScan(basePackages ={ "com.metoo.nspm"})//只用注解配置时，需要扫描包
@SpringBootApplication(exclude = DataSourceAutoConfiguration.class)
public class Application extends SpringBootServletInitializer {

    public static void main(String[] args) {
        Long time=System.currentTimeMillis();
        SpringApplication.run(Application.class);
        System.out.println("===应用启动耗时："+(System.currentTimeMillis()-time)+"===");
    }

    @Override
    protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
        return builder.sources(this.getClass());
    }

//     在容器启动成功后的最后一步回调（类似开机自启动）
    @Component
    @Order(0)
    static class Runner implements CommandLineRunner{

        @Autowired
        private ITopologyTokenService topologyTokenService;
        @Autowired
        private TestInitService testInitService;

        @Override
        public void run(String... args) {
            Long time=System.currentTimeMillis();
            System.out.println("begin======================================");
//            this.topologyTokenService.initToken();
//            this.testInitService.init();
            System.out.println("Init time：" + (System.currentTimeMillis() - time));
        }
    }

}

