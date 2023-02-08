package com.metoo.nspm.core.config.dbconfig;

import org.apache.ibatis.session.SqlSessionFactory;
import org.mybatis.spring.SqlSessionFactoryBean;
import org.mybatis.spring.SqlSessionTemplate;
import org.mybatis.spring.annotation.MapperScan;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.support.PathMatchingResourcePatternResolver;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;

import javax.sql.DataSource;

/**
 * topology数据库配置
 */
@Configuration
@MapperScan(basePackages = "com.metoo.nspm.core.mapper.topology", sqlSessionTemplateRef = "topologySqlSessionTemplate")
public class TopologyDataSourceConfig {

    // 主数据源 topology数据源
    @Bean("topologySqlSessionFactory")
    public SqlSessionFactory topologySqlSessionFactory(@Qualifier("topologyDataSource") DataSource dataSource) throws Exception {
        SqlSessionFactoryBean sqlSessionFactory = new SqlSessionFactoryBean();
        sqlSessionFactory.setDataSource(dataSource);
        sqlSessionFactory.setMapperLocations(new PathMatchingResourcePatternResolver().
                getResources("classpath*:mapper/topology/*.xml"));
        return sqlSessionFactory.getObject();
    }

    @Bean(name = "topologyTransactionManager")
    public DataSourceTransactionManager topologyTransactionManager(@Qualifier("topologyDataSource") DataSource dataSource) {
        return new DataSourceTransactionManager(dataSource);
    }

    @Bean(name = "topologySqlSessionTemplate")
    public SqlSessionTemplate topologySqlSessionTemplate(@Qualifier("topologySqlSessionFactory") SqlSessionFactory sqlSessionFactory) {
        return new SqlSessionTemplate(sqlSessionFactory);
    }
}
