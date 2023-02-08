package com.metoo.nspm.dto.zabbix;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@ApiModel("用户宏")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class UserMacroDTO extends ParamsDTO{

    private Boolean globalmacro;

    private String globalmacroid;// 全局宏Id
    private String value;// 宏的值
    private String macro;// 宏的字符串
    private String type;// 宏的类型 1-密文宏 2-密钥宏
    private String description;// 宏的描述信息

    private String hostmacroid;// 主机宏Id
    private String hostid;// 主机Id
}
