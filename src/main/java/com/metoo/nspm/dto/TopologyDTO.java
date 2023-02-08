package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.Topology;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

import java.util.Date;
import java.util.Set;


@Data
@Accessors
@AllArgsConstructor
@NoArgsConstructor
public class TopologyDTO extends PageDto<Topology> {

    private Long id;
    private String name;
    private Date updateTime;
    private Boolean isDefault;
    private String description;
    private Long groupId;
    private String groupName;
    private Object content;
    private Long userId;
    private String userName;
    private Set<Long> groupIds;
    private String baseUrl;
    private Date time;

}
