package com.metoo.nspm.vo;

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
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class LicenseVo {

    @ApiModelProperty("开始时间")
    private Long startTime;
    @ApiModelProperty("结束时间")
    private Long endTime;
    @ApiModelProperty("授权时间")
    private int licenseDay;
    @ApiModelProperty("License类型 0：试用版 1，授权版 2：终身版")
    private String type;
    @ApiModelProperty("License版本号")
    private String licenseVersion;

    // 授权信息
    @ApiModelProperty("授权防火墙")
    private int licenseFireWall;
    @ApiModelProperty("授权路由/交换")
    private int licenseRouter;
    @ApiModelProperty("授权主机数")
    private int licenseHost;
    @ApiModelProperty("授权模拟网关")
    private int licenseUe;
    @ApiModelProperty("已使用")
    private int useDay;
    @ApiModelProperty("未使用")
    private int surplusDay;

    @ApiModelProperty("以导入防火墙")
    private int useFirewall;
    @ApiModelProperty("以导入路由交换")
    private int useRouter;
    @ApiModelProperty("以导入主机数")
    private int useHost;
    @ApiModelProperty("以导入模拟网关")
    private int useUe;

}
