package com.metoo.nspm.core.config.websocket.process.ssh.constant;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class ConstantPool {
    public static final String USER_UUID_KEY = "user_uuid";
    public static final String WEBSSH_OPERATE_CONNECT = "connect";
    public static final String WEBSSH_OPERATE_COMMAND = "command";
    public static final String WEBSSH_OPERATE_INTIME = "intime";
    public static final Map<String, Object> SSHMAP = new ConcurrentHashMap();

    public ConstantPool() {
    }
}