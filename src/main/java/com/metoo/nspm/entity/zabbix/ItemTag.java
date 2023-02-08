package com.metoo.nspm.entity.zabbix;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@ApiModel("item 标签类")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ItemTag {

    private Long itemtagid;
    private Long itemid;
    private String tag;
    private String value;
    private String name;
    private String description;
    private String mask;
    private String ip;
    private String up;
    private String mac;
    private List<Item> items;

}
