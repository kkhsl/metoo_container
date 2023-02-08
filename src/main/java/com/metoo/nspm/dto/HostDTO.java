package com.metoo.nspm.dto;

import com.metoo.nspm.dto.page.PageDto;
import com.metoo.nspm.entity.nspm.Host;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class HostDTO extends PageDto<Host> {

    private Long id;
    private String name;
    private String uuid;
    private String ip1;
    private String ip2;
    private String description;
    private Long userId;
    private String userName;

}
