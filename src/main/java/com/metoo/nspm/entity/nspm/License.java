package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

/**
 * Licens验证方式
 *  第一种方式：系统文件
 *  第二种方式：注册表 *
 *  第三种方式：远程服务端
 */
@ApiModel("软件授权")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class License extends IdEntity {

    @ApiModelProperty("申请码,系统唯一序列号")
    private String systemSN;

    @ApiModelProperty("授权码")
    private String license;

    @ApiModelProperty("开始时间")
    private Long startTime;

    @ApiModelProperty("结束时间")
    private Long endTime;

    @ApiModelProperty("过期时间")
    private String expireTime;

    @ApiModelProperty("License类型 0：试用版 1，授权版 2：终身版")
    private String type;

    @ApiModelProperty("License状态  0：未过期 1:未授权 2：已过期")
    private Integer status;

    @ApiModelProperty("SN码来源 0：同一来源 1：不同来源 不同来源则不允许使用")
    private Integer from;

    @ApiModelProperty("License版本号")
    private String licenseVersion;

    @ApiModelProperty("以导入防火墙")
    private int useFirewall;
    private boolean checkFirewall = false;
    @ApiModelProperty("以导入路由交换")
    private int useRouter;
    private boolean checkRouter = false;
    @ApiModelProperty("以导入主机数")
    private int useHost;
    private boolean checkHost = false;
    @ApiModelProperty("以导入模拟网关")
    private int useUe;
    private boolean checkUe = false;

    @ApiModelProperty("授权防火墙")
    private int licenseFireWall;
    @ApiModelProperty("授权路由/交换")
    private int licenseRouter;
    @ApiModelProperty("授权主机数")
    private int licenseHost;
    @ApiModelProperty("授权模拟网关")
    private int licenseUe;

}
