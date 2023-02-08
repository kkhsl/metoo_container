package com.metoo.nspm.dto;

import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.List;

@ApiModel("AssetDto")
@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class AssetDto {

    private Integer limit;
    private Integer page;
    private Object val;
    /*{
            "name": "zabbix",
            "manufacturerId": 2,
            "ipAddress": "1.1.1.1",
            "assetGroup": 54,
            "assetGroupName": "V1",
            "importanceLevel": 1,
            "subnetName": "2.2.2.2",
            "zoneName": "aaa",
            "softwareName": "303",
            "softwarePort": "22",
            "softwareProtocol": "1"
    }*/
    private String ipAddress;
    @ApiModelProperty("备注描述")
    private String assetDesc;
    @ApiModelProperty("主机分组")
    private String assetGroup;
    @ApiModelProperty("主机分组")
    private String assetGroupName;
    private List assetIpList;
    private List assetIptablesList;
    private List hostComputerSoftwareList;
    private Integer importanceLevel;
    private Integer manufacturerId;
    @ApiModelProperty("主机名称")
    private String name;
    @ApiModelProperty("主机厂商")
    private String productModel;
    private Integer typeId;
    private String assetUuid;
    private String uuids;
    private String uuid;
    private String description;
    private Integer id;
    private Integer parentid;
    private List ids;
}
