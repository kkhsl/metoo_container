package com.metoo.nspm.core.config.shiro;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.web.bind.annotation.RestController;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.ArrayList;

/**
 * <p>
 *     Title: SwaggerConfig.java
 * </p>
 *
 * <p>
 *     Description: Swagger控制器; Swagger首页：
 * </p>
 *
 * <p>
 *     author: pers hkk
 * </p>
 *
 */
@Configuration
@EnableSwagger2
public class SwaggerConfig {


    @Bean
    public Docket docket1(Environment environment){
        Profiles profiles = Profiles.of("dev");
        boolean flag = environment.acceptsProfiles(profiles);

        // 获取项目环境
        return new Docket(DocumentationType.SWAGGER_2)
                .groupName("swagger") ;
    }

    @Bean
    public Docket docket(Environment environment){
        Profiles profiles = Profiles.of("dev");
        boolean flag = environment.acceptsProfiles(profiles);

        // 获取项目环境
        return new Docket(DocumentationType.SWAGGER_2)
                .groupName("默认文档")
                .apiInfo(apiInfo())
                .enable(flag)
                .select()
                // RequestHandlerSelectors：配置扫描方式
                //basePackage：扫描指定包
                //any：扫描全部
                //non：都不扫描
                //withClassAnnotation：扫描类上的注解
                //withMethodAnnotation：扫描方法上的注解
                .apis(RequestHandlerSelectors.withClassAnnotation(RestController.class))
                .paths(PathSelectors.ant("/admin/**"))
                .build();
    }

    public ApiInfo apiInfo(){
        Contact contact = new Contact("HKK", "httpclient://www.apache.org/licenses/LICENSE-2.0", "460751446@qq.com");
        return new ApiInfo(
                "Metoo Api Decument"
                , "屎壳郎推地球！"
                , "1.0"
                , "urn:tos"
                , contact
                , "Apache 2.0"
                , "httpclient://www.apache.org/licenses/LICENSE-2.0"
                , new ArrayList());
    }

    /**
     * 防止@EnableMvc把默认的静态资源路径覆盖了，手动设置的方式
     *
     * @param registry
     */
  /*  @Override
    protected void addResourceHandlers(ResourceHandlerRegistry registry) {
        // 解决静态资源无法访问
        registry.addResourceHandler("/**").addResourceLocations("classpath:/static/");
        // 解决swagger无法访问
        registry.addResourceHandler("/swagger-ui.html").addResourceLocations("classpath:/META-INF/resources/");
        // 解决swagger的js文件无法访问
        registry.addResourceHandler("/webjars/**").addResourceLocations("classpath:/META-INF/resources/webjars/");

    }*/
}
