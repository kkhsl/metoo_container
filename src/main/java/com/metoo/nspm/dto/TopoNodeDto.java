package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.TopoNode;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
@ApiModel("节点配置")
public class TopoNodeDto<T> extends PageDto<TopoNode> {

    @ApiModelProperty("页数")
    private Integer start;
    @ApiModelProperty("每页条数")
    private Integer limit;
    private Integer size;
    @ApiModelProperty("0：防火墙 1：路由交换 2：负载均衡 3：模拟网关 4：网闸 5：终端检测响应")
    private String type;
    @ApiModelProperty("")
    private Integer display;
    @ApiModelProperty("搜索关键字")
    private String filter;
    @ApiModelProperty("1：手工采集 2：在线采集")
    private String origin;
    @ApiModelProperty("")
    private String branchLevel;
    @ApiModelProperty("排序 1：采集成功 2：采集失败")
    private String state;
    @ApiModelProperty("供应商")
    private String vendor;
    @ApiModelProperty("缺省为null true:不参与计算 false：参与计算")
    private String skipAnalysis;
    @ApiModelProperty("缺省为null true:同进同出开启 false：同进同出关闭")
    private String toSameInbound;
    @ApiModelProperty("缺省为null true:二层设备（是）二层设备（否")
    private String layerTwoDevice;

    private String uuid;
    private String id;

    @ApiModelProperty("业务子网自动学习 true：开启 false：关闭  业务网段")
    private String businessSubnet;

    @ApiModelProperty("自动学习 true：开启 false：关闭")
    private String infBusinessSubnet;

    @ApiModelProperty("设备接口名称")
    private String interfaceName;

    @ApiModelProperty("设备UUID")
    private String deviceUuid;

    @ApiModelProperty("")
    private String textRefId;

    @ApiModelProperty("排除业务网段")
    private String ip4ExcludeAddressRangePOS;
    @ApiModelProperty("补充业务网段")
    private String ip4IncludeAddressRangePOS;
    @ApiModelProperty("全局排除业务网段")
    private String ip4WholeExcludeAddressRangePOS;

    // 采集历史
    private String _dc;
    private String ip;

    // 参与路径计算
    // private String skipAnalysis;
    private String nodeIds;

    //变更监控
    private Integer page;
    private Integer psize;
    private String revisionId;
    private Integer change;

    //保存
    @ApiModelProperty("设备名称")
    private String deviceName;
    private String deviceIp;

    private String defaultRout;

    // 采集配置
    private Integer pageIndex;
    private String selectBox;
    private String id2;

    // 保存
    private String description;
    private String nodeGroup;
    private String modelNumber;
    private String includeRouting;
    private String version;
    private String version1;
    private String controllerId;
    private String portNumber;
    private Integer timeout;
    private String credentialUuid;
    private String pushCredentialUuid;
    private String deviceTemplateId;
    private String hostAddress;
    private String pluginId;
    private String vendorId;
    private String version2;
    private String vendorName;
    private String deviceType;
    private String gatherCycle;
    private String nodeId;
    private String customPythonPath;
    private String gatherId;
    private String charset;
    private String webHref;
    private String isChangeWarn;
    private String credenGroupManagerControllertialUuid;
    private String ips;

    private String cmbDeviceType;
    private String cmbDeviceVendor;

    private Integer pageNum;
    private String order;
    private String sort;
    private String layerName;

    private String baseUrl;
    private Object content;
    private String layerUuid;
    private String name;
    private String layerUuids;

    private String subnetUuid;
    private String opUuid;

    private Object routeStr;

    private List interfaces;
    private List beginFlow;

    private String dstNodeId;
    private String ipType;
    private String isPathOnly;
    private String requestType;
    private String srcNodeId;
    private String trustLevel;
    private List uuidList;
    private List tags;
    private String tagsOp;
    private List exclusives;
    private String desc;
    private String ids;
    private String ip4BaseAddress;
    private String ip4MaskLength;
    private String ip4Address;
    private String linkedDevice;
    private String linkedDeviceName;
    private String subnetType;
    private String subnetId;
    private Object val;
    private Integer assertGroup;
    private String ipAddress;
    private String zoneUuid;
    private String startTime;
    private String endTime;
    private String devId;
    private String skipHost;
    private List elements;
    private String topoModType;
    private String ip4Addr;
    private String currDevicePathStatus;
    private Object device;
    private List deviceFlows;
    private String inIfId;
    private String outIfId;
    private Object inInterface;
    private Object outInterface;
    private String createdTime;
    private Object iprange;
    private String lastModifiedTime;
    private String subnetMark;
    private String subnetUserType;

    // zabbix
    private Long time_till;
    private Long time_from;
    private boolean flag;

}
