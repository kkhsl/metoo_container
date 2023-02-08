package com.metoo.nspm.entity.nspm;

import com.metoo.nspm.core.domain.IdEntity;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Date;
import java.util.Objects;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ProblemTemp extends IdEntity {

    private Integer objectid;
    private String name;
    private String deviceName;
    private String interfaceName;
    private String hostids;
    private Long clock;
    private String uuid;
    private String ip;
    private String severity;
    private String event;
    private Integer suppressed;
    private Integer status;
    private Date restoreTime;

}
