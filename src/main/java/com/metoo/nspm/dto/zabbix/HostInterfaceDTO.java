package com.metoo.nspm.dto.zabbix;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.Accessors;

@Data
@Accessors(chain = true)
@AllArgsConstructor
@NoArgsConstructor
public class HostInterfaceDTO  extends ParamsDTO  {

    private String ip;
    private String hostids;
    private String interfaceid;
    private String port;
    private String version;
    private String bulk;
    private String community;
    private String securityname;
    private String contextname;
    private String securitylevel;
    private Object details;

}
