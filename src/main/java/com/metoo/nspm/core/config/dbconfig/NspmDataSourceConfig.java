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
 * nspm数据库配置
 */
@Configuration
@MapperScan(basePackages = "com.metoo.nspm.core.mapper.nspm", sqlSessionTemplateRef = "nspmSqlSessionTemplate")
public class NspmDataSourceConfig {

    // 主数据源 nspm数据源
    @Primary
    @Bean("nspmSqlSessionFactory")
    public SqlSessionFactory nspmSqlSessionFactory(@Qualifier("nspmDataSource") DataSource dataSource) throws Exception {
        SqlSessionFactoryBean sqlSessionFactory = new SqlSessionFactoryBean();
        sqlSessionFactory.setDataSource(dataSource);
        sqlSessionFactory.setMapperLocations(new PathMatchingResourcePatternResolver().
                getResources("classpath*:mapper/nspm/*.xml"));
        return sqlSessionFactory.getObject();
    }

    @Primary
    @Bean(name = "nspmTransactionManager")
    public DataSourceTransactionManager nspmTransactionManager(@Qualifier("nspmDataSource") DataSource dataSource) {
        return new DataSourceTransactionManager(dataSource);
    }

    @Primary
    @Bean(name = "nspmSqlSessionTemplate")
    public SqlSessionTemplate nspmSqlSessionTemplate(@Qualifier("nspmSqlSessionFactory") SqlSessionFactory sqlSessionFactory) {
        return new SqlSessionTemplate(sqlSessionFactory);
    }
}
