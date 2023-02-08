package com.metoo.nspm.entity.zabbix;

import io.swagger.annotations.ApiModel;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.apache.ibatis.annotations.Arg;

import java.util.ArrayList;
import java.util.List;

@ApiModel("主机：Item")
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Item {

    private Long itemid;
    private String boardType;
    private List<ItemTag> itemTags = new ArrayList();
}
