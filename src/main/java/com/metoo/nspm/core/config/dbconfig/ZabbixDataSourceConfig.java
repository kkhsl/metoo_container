package com.metoo.nspm.core.config.dbconfig;

import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;

import javax.sql.DataSource;

@Configuration
@MapperScan(basePackages = "com.metoo.nspm.core.mapper.zabbix", sqlSessionTemplateRef = "zabbixSqlSessionTemplate")
public class ZabbixDataSourceConfig {

    // zabbix 数据源
    @Bean("zabbixSqlSessionFactory")
    public SqlSessionFactory zabbixSqlSessionFactory(@Qualifier("zabbixDataSource") DataSource dataSource) throws Exception {
        SqlSessionFactoryBean sqlSessionFactory = new SqlSessionFactoryBean();
        sqlSessionFactory.setDataSource(dataSource);
        sqlSessionFactory.setMapperLocations(new PathMatchingResourcePatternResolver().
                getResources("classpath*:mapper/zabbix/*.xml"));
        return sqlSessionFactory.getObject();
    }

    @Bean(name = "zabbixTransactionManager")
    public DataSourceTransactionManager zabbixTransactionManager(@Qualifier("zabbixDataSource") DataSource dataSource) {
        return new DataSourceTransactionManager(dataSource);
    }

    @Bean(name = "zabbixSqlSessionTemplate")
    public SqlSessionTemplate zabbixSqlSessionTemplate(@Qualifier("zabbixSqlSessionFactory") SqlSessionFactory sqlSessionFactory) {
        return new SqlSessionTemplate(sqlSessionFactory);
    }

}
