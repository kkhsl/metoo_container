package com.metoo.nspm.core.jwt.config;

import com.metoo.nspm.core.jwt.filter.JwtFilter;
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.spring.LifecycleBeanPostProcessor;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.aop.framework.autoproxy.DefaultAdvisorAutoProxyCreator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.HashMap;
import java.util.Map;

/**
 * @description
 *
 * @author HKK
 *
 * @create 2023-02-09 15:39
 *
 */
@Configuration
public class JwtShiroConfig {

    /**
     * 禁用Session，设置JwrReam代替shiroReam
     * @param jwtRealm
     * @return
     */
    @Bean
    public DefaultWebSecurityManager defaultWebSecurityManager(JwtRealm jwtRealm) {
        DefaultWebSecurityManager defaultWebSecurityManager = new DefaultWebSecurityManager();
        defaultWebSecurityManager.setRealm(jwtRealm);
        // 关闭shiro自带的session
        DefaultSubjectDAO defaultSubjectDAO = new DefaultSubjectDAO();
        DefaultSessionStorageEvaluator sessionStorageEvaluator = new DefaultSessionStorageEvaluator();
        sessionStorageEvaluator.setSessionStorageEnabled(false);
        defaultSubjectDAO.setSessionStorageEvaluator(sessionStorageEvaluator);
        defaultWebSecurityManager.setSubjectDAO(defaultSubjectDAO);

        return defaultWebSecurityManager;
    }

    /**
     *  配置过滤器
     * @param defaultWebSecurityManager
     * @return
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilterFactoryBean(DefaultWebSecurityManager defaultWebSecurityManager) {

        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();

        shiroFilterFactoryBean.setSecurityManager(defaultWebSecurityManager);

        // 自定义过滤器组，配置系统受限资源
        Map<String, Filter> filterMap = new HashMap<>();
        filterMap.put("jwt", new JwtFilter());
        shiroFilterFactoryBean.setFilters(filterMap);

        // 编写过滤规则
        Map<String, String> filterRuleMap = new HashMap<>();

        // 访问 /unauthorized/**时直接放行
        filterRuleMap.put("/jwt/login", "anon");// 放行登录
        // 放行认证授权异常路径
        filterRuleMap.put("/admin/auth/401", "anon");
        filterRuleMap.put("/admin/auth/403", "anon");

        // 其他所有请求通过我们自己的JWT Filter
        filterRuleMap.put("/**", "jwt");

        // 设置无权限时跳转url
        shiroFilterFactoryBean.setLoginUrl("/admin/auth/401");
        shiroFilterFactoryBean.setUnauthorizedUrl("/admin/auth/403");

        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterRuleMap);


        return shiroFilterFactoryBean;
    }



    /**
     * 添加注解支持，如果不加的话很有可能注解失效
     */
    @Bean
    public DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator(){

        DefaultAdvisorAutoProxyCreator defaultAdvisorAutoProxyCreator=new DefaultAdvisorAutoProxyCreator();
        defaultAdvisorAutoProxyCreator.setProxyTargetClass(true);
        return defaultAdvisorAutoProxyCreator;
    }

    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(DefaultWebSecurityManager defaultWebSecurityManager){
        AuthorizationAttributeSourceAdvisor advisor = new AuthorizationAttributeSourceAdvisor();
        advisor.setSecurityManager(defaultWebSecurityManager);
        return advisor;
    }

    @Bean
    public LifecycleBeanPostProcessor lifecycleBeanPostProcessor() {
        return new LifecycleBeanPostProcessor();
    }

}
