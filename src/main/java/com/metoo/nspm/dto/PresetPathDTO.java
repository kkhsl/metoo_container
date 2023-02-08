package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.PresetPath;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PresetPathDTO extends PageDto<PresetPath> {
    private Long id;
    private String name;
    private Long topologyId;
    private String topologyName;
    private String content;
    private Long userId;
    private String userName;
    private String srcIp;
    private String srcMask;
    private String destIp;
    private String destMask;

}
