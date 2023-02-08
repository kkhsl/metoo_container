package com.metoo.nspm.core.config.website;

import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

import org.springframework.stereotype.Component;

@Component
@Configuration
@PropertySource(value= "classpath:application-properties.yml",encoding = "UTF-8") //加载配置文件信息
@Data
public class Properties {

    @Value("${batchImportNeFileName}")
    private String batchImportNeFileName;
    @Value("${batchImportDeviceFileName}")
    private String batchImportDeviceFileName;


}
