package com.metoo.nspm.core.ssh.service.imple;

import com.alibaba.fastjson.JSONObject;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.pagehelper.util.StringUtil;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelSftp;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.metoo.nspm.core.config.websocket.process.ssh.constant.ConstantPool;
import com.metoo.nspm.core.config.websocket.process.ssh.pojo.SSHConnectInfo;
import com.metoo.nspm.core.config.websocket.process.ssh.pojo.WebSSHData;
import com.metoo.nspm.core.config.websocket.process.ssh.service.impl.WebSSHServiceImpl;
import com.metoo.nspm.core.mapper.nspm.NodeMapper;
import com.metoo.nspm.core.service.nspm.ICredentialService;
import com.metoo.nspm.core.service.nspm.INetworkElementService;
import com.metoo.nspm.core.ssh.excutor.ExecutorDto;
import com.metoo.nspm.core.ssh.excutor.ExtendedRunnable;
import com.metoo.nspm.core.websocket.api.NetWorkManagerApi;
import com.metoo.nspm.entity.nspm.Credential;
import com.metoo.nspm.entity.nspm.NetworkElement;
import org.apache.commons.lang3.ObjectUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.socket.WebSocketSession;
import sun.misc.BASE64Decoder;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.*;
import java.util.concurrent.Executor;

@Service("commentWebSshService")
public class DiscoverWebSSHServiceImpl extends WebSSHServiceImpl {
    private static final Logger log = LoggerFactory.getLogger(DiscoverWebSSHServiceImpl.class);
    private Logger logger = LoggerFactory.getLogger(DiscoverWebSSHServiceImpl.class);
    @Autowired
    @Qualifier("discoverSshExecutor")
    private Executor discoverSshExecutor;
    @Autowired
    private INetworkElementService networkElementService;
    @Autowired
    private ICredentialService credentialService;
//    @Autowired
//    DeviceSshDataService sshDataService;
//    @Autowired
//    DiscoverDeviceService deviceService;
//    @Autowired
//    NodeMapper nodeMapper;
//    @Autowired
//    CredentialMapper credentialMapper;

    public DiscoverWebSSHServiceImpl() {
    }

    public void recvHandle(String buffer, WebSocketSession session) {
        String userId = String.valueOf(session.getAttributes().get("user_uuid"));
        ObjectMapper objectMapper = new ObjectMapper();

        try {
            final WebSSHData webSSHData = objectMapper.readValue(buffer, WebSSHData.class);
            if ("connect".equals(webSSHData.getOperate())) {
                final SSHConnectInfo sshConnectInfo = (SSHConnectInfo) ConstantPool.SSHMAP.get(userId);
                this.discoverSshExecutor.execute(new ExtendedRunnable(new ExecutorDto(userId, "", "", new Date())) {
                    protected void start() throws Exception {
                        try {
//                        DiscoverWebSSHServiceImpl.this.connectToSSH(sshConnectInfo, webSSHData, session);
//                        DiscoverWebSSHServiceImpl.this.connectToSSHTest(sshConnectInfo, session, "192.168.5.191",
//                                "metoo@domain", "Metoo@89745000");
                            DiscoverWebSSHServiceImpl.this.connectToSSH(sshConnectInfo, webSSHData, session);
                        } catch (IOException | JSchException var2) {
                            DiscoverWebSSHServiceImpl.this.logger.error("webssh连接异常");
                            DiscoverWebSSHServiceImpl.this.logger.error("异常信息:{}", var2.getMessage());
                            DiscoverWebSSHServiceImpl.this.close(session);
                            // 返回异常信息
                            Map map = new HashMap();
                            map.put("msg", var2.getLocalizedMessage()   );
                            sendMessage(session, JSONObject.toJSONBytes(map));
                        }
                    }
                });
            }else if ("command".equals(webSSHData.getOperate())) {
                String command = webSSHData.getCommand();
                SSHConnectInfo sshConnectInfo = (SSHConnectInfo) ConstantPool.SSHMAP.get(userId);
                if (sshConnectInfo != null) {
                    try {
                        this.transToSSH(sshConnectInfo.getChannel(), command);
                    } catch (IOException var9) {
                        this.logger.error("webssh连接异常");
                        this.logger.error("异常信息:{}", var9.getMessage());
                        this.close(session);
                    }
                }
            }
        } catch (IOException var10) {
            this.logger.error("Json转换异常");
            this.logger.error("异常信息:{}", var10.getMessage());
            return;
        }
    }

//    private void connectToSSH(SSHConnectInfo sshConnectInfo, WebSSHData webSSHData, WebSocketSession webSocketSession) throws JSchException, IOException {
//        Session session = null;
//        Properties config = new Properties();
//        config.put("StrictHostKeyChecking", "no");
//        String deviceUuid = webSSHData.getDeviceUuid();
//        if (!StringUtils.isEmpty(deviceUuid)) {
//            Integer type = webSSHData.getType();
//            if (null == type) {
//                type = 1;
//            }
//
//            if (1 == type) {
//                DiscoverDevice device = this.deviceService.getDiscoverDeviceByUuid(deviceUuid);
//                if (device == null) {
//                    return;
//                }
//
//                DeviceCredential credential = this.sshDataService.getSshData(device.getCredentialUuid());
//                if (credential == null) {
//                    return;
//                }
//
//                session = sshConnectInfo.getjSch().getSession(credential.getLoginName(), device.getIpAddress(), 22);
//                if (!StringUtils.isEmpty(credential.getLoginPassword())) {
//                    session.setPassword(Encodes.decodeBase64Key(credential.getLoginPassword()));
//                }
//            } else if (2 == type) {
//                Node node = this.nodeMapper.getTheNodeByUuid(deviceUuid);
//                if (ObjectUtils.isEmpty(node)) {
//                    return;
//                }
//
//                String credentialUuid = node.getCredentialUuid();
//                String ipv4 = node.getIp();
//                if (node.getIp().contains("(")) {
//                    String ipAddress = node.getIp().substring(0, node.getIp().lastIndexOf("("));
//                    Node mainNode = this.nodeMapper.getNodeByIp(ipAddress);
//                    if (!ObjectUtils.isEmpty(mainNode)) {
//                        credentialUuid = mainNode.getCredentialUuid();
//                        ipv4 = mainNode.getIp();
//                    }
//                }
//
//                if (org.apache.commons.lang3.StringUtils.isEmpty(credentialUuid)) {
//                    return;
//                }
//
//                CredentialEntity credentialEntity = this.credentialMapper.queryCredentialByUuid(credentialUuid);
//                if (!TotemsIp4Utils.isIp4(ipv4)) {
//                    String trueIpv4 = TotemsIp4Utils.getMatcherIP4(ipv4);
//                    ipv4 = trueIpv4;
//                }
//
//                session = sshConnectInfo.getjSch().getSession(credentialEntity.getLoginName(), ipv4, 22);
//                log.info("credentialEntity:{}", JSONObject.toJSONString(credentialEntity));
//                BASE64Decoder decoder = new BASE64Decoder();
//                String pwd = new String(decoder.decodeBuffer(credentialEntity.getLoginPassword()), "UTF-8");
//                log.info("设备：{},原密码：{}", node.getIp(), credentialEntity.getLoginPassword());
//                if (pwd.length() > 10) {
//                    pwd = pwd.substring(3);
//                    pwd = pwd.substring(0, pwd.length() - 7);
//                }
//
//                if (!TotemsIp4Utils.isIp4(ipv4)) {
//                    String masterIP4 = TotemsIp4Utils.getMatcherIP4(ipv4);
//                    if (org.apache.commons.lang3.StringUtils.isNotBlank(masterIP4)) {
//                        node.setIp(masterIP4);
//                    }
//                }
//
//                log.info("连接shell->host:{},port:{},username:{},pwd:{}", new Object[]{node.getIp(), node.getPortNumber(), credentialEntity.getLoginName(), credentialEntity.getLoginPassword()});
//                session.setPassword(pwd);
//            }
//
//            session.setConfig(config);
//            session.setDaemonThread(true);
//            session.connect(30000);
//            Channel channel = session.openChannel("shell");
//            channel.connect(3000);
//            sshConnectInfo.setChannel(channel);
//            this.transToSSH(channel, "\r");
//            InputStream inputStream = channel.getInputStream();
//
//            try {
//                byte[] buffer = new byte[1024];
//                boolean var24 = false;
//
//                int i;
//                while ((i = inputStream.read(buffer)) != -1) {
//                    this.sendMessage(webSocketSession, Arrays.copyOfRange(buffer, 0, i));
//                }
//            } finally {
//                session.disconnect();
//                channel.disconnect();
//                if (inputStream != null) {
//                    inputStream.close();
//                }
//
//            }
//
//        }
//    }

    public void connectToSSH(SSHConnectInfo sshConnectInfo, WebSSHData webSSHData, WebSocketSession webSocketSession) throws JSchException, IOException {
        String deviceUuid = webSSHData.getDeviceUuid();
        if (!StringUtils.isEmpty(deviceUuid)) {
            NetworkElement ne = this.networkElementService.selectObjByUuid(deviceUuid);
            if (ObjectUtils.isEmpty(ne)) {
                return;
            }
            if (ne.isPermitConnect()) {
                Credential credential = this.credentialService.getObjById(ne.getCredentialId());
                if (ObjectUtils.isEmpty(credential)) {
                    return;
                }
                Session session1 = sshConnectInfo.getjSch().getSession(credential.getLoginName(), ne.getIp(), ne.getPort());
                Session session = sshConnectInfo.getjSch().getSession(credential.getLoginName(), ne.getIp(), ne.getPort());
                //        BASE64Decoder decoder = new BASE64Decoder();
                //        String pwd = new String(decoder.decodeBuffer(password), "UTF-8");
                //        if (pwd.length() > 10) {
                //            pwd = pwd.substring(3);
                //            pwd = pwd.substring(0, pwd.length() - 7);
                //        }
                if(!StringUtil.isEmpty(credential.getLoginPassword())){
                    session.setPassword(credential.getLoginPassword());
                }
                Properties config = new Properties();
                config.put("StrictHostKeyChecking", "no");
//                config.put("PasswordAuthentication", "yes");
                session.setConfig(config);
                session.setDaemonThread(true);
                session.connect(30000);
                //shell 建立通道
                Channel channel = session.openChannel("shell");// sftp
                // 连接通道
                channel.connect(3000);

//                if (channel != null) {
//                    OutputStream outputStream = channel.getOutputStream();
//                    outputStream.write("sudo -S ".getBytes());
//                    outputStream.flush();
//                }

                //sftp 通道
                //        ChannelSftp channelSftp= (ChannelSftp) session.openChannel("sftp");
                //连接通道
                //        channelSftp.connect();

                sshConnectInfo.setChannel(channel);
                this.transToSSH(channel, "\r");

                InputStream inputStream = channel.getInputStream();

                try {
                    byte[] buffer = new byte[1024];
                    boolean var24 = false;

                    int i;
                    while ((i = inputStream.read(buffer)) != -1) {
                        this.sendMessage(webSocketSession, Arrays.copyOfRange(buffer, 0, i));
                    }
                } finally {
                    session.disconnect();
                    channel.disconnect();
                    if (inputStream != null) {
                        inputStream.close();
                    }
                }
            }
        }
    }

    public void connectToSSHTest(SSHConnectInfo sshConnectInfo, WebSocketSession webSocketSession,
                 String ipv4, String loginName, String password) throws JSchException, IOException {

        Session session = sshConnectInfo.getjSch().getSession(loginName, ipv4, 22);

//        BASE64Decoder decoder = new BASE64Decoder();
//        String pwd = new String(decoder.decodeBuffer(password), "UTF-8");
//        if (pwd.length() > 10) {
//            pwd = pwd.substring(3);
//            pwd = pwd.substring(0, pwd.length() - 7);
//        }
        session.setPassword(password);

        Properties config = new Properties();
        config.put("StrictHostKeyChecking", "no");
        session.setConfig(config);
        session.setDaemonThread(true);
        session.connect(30000);
        //shell 建立通道
        Channel channel = session.openChannel("shell");
        // 连接通道
        channel.connect(3000);

        //sftp 通道
//        ChannelSftp channelSftp= (ChannelSftp) session.openChannel("sftp");
        //连接通道
//        channelSftp.connect();

        sshConnectInfo.setChannel(channel);
        this.transToSSH(channel, "\r");

        InputStream inputStream = channel.getInputStream();

        try

        {
            byte[] buffer = new byte[1024];
            boolean var24 = false;

            int i;
            while ((i = inputStream.read(buffer)) != -1) {
                this.sendMessage(webSocketSession, Arrays.copyOfRange(buffer, 0, i));
            }
        } finally

        {
            session.disconnect();
            channel.disconnect();
            if (inputStream != null) {
                inputStream.close();
            }

        }
    }

    public void transToSSH(Channel channel, String command) throws IOException {
        if (channel != null) {
            OutputStream outputStream = channel.getOutputStream();
            outputStream.write(command.getBytes());
            outputStream.flush();
        }

    }
}