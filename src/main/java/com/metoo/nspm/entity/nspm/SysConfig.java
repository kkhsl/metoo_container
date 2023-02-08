package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.*;

/**
 * <p>
 *     Title：系统配置
 * </p>
 *
 * <p>
 *     Description: 系统配置管理类；系统基础配置。
 * </p>
 *
 * <author>
 *     HKK
 * </author>
 */

@ApiModel("系统配置实体类")
/*@EqualsAndHashCode //实现equals()和hashCode()
@ToString  //实现toString()*/
/*@Cleanup  //关闭流
@Synchronized //对象上同步
@SneakyThrows //抛出异常*/
@NoArgsConstructor  //注解在类上；为类提供一个无参的构造方法
@AllArgsConstructor  //注解在类上；为类提供一个全参的构造方法
@Data  //注解在类上；提供类所有属性的 getting 和 setting 方法，此外还提供了equals、canEqual、hashCode、toString 方法
@Setter  //可用在类或属性上；为属性提供 setting 方法
@Getter  //可用在类或属性上；为属性提供 getting 方法
public class SysConfig extends IdEntity {

    @ApiModelProperty("网站标题")
    private String title;

    @ApiModelProperty("推流地址IP")
    private String ip;

    @ApiModelProperty("推流地址 例：rtmp://lk.soarmall.com:1935/hls")
    private String rtmp;

    @ApiModelProperty("视频文件上传路径 例: /www/wwwroot/lk.soarmall.com/hls")
    private String path;

    @ApiModelProperty("转mp4文件名称")
    private String temp;

    @ApiModelProperty("视频文件上传路径")
    private String videoFilePath;

    @ApiModelProperty("视频文件上传路径")
    private String photoFilePath;

    @ApiModelProperty("域名")
    private String domain;

    @ApiModelProperty("文件保存地址")
    private String uploadFilePath;

    @ApiModelProperty("是否开启审核0：未开启 1：开启")
    private Integer videoAudit;

    @ApiModelProperty("应用唯一标识：暂时只使用AppId")
    private String appId;

    @ApiModelProperty("策略可视化平台url")
    private String nspmUrl;
    @ApiModelProperty("策略可视化平台Token")
    private String nspmToken;
    private String testToken;

    private String ntasUrl;
    private String ntasProtocol;
    private String ntasToken;

}
