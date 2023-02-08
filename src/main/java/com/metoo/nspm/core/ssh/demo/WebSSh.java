package com.metoo.nspm.core.ssh.demo;

import com.alibaba.fastjson.JSONObject;
import com.jcraft.jsch.Channel;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.metoo.nspm.core.config.websocket.process.ssh.pojo.SSHConnectInfo;
import com.metoo.nspm.core.utils.network.IpUtil;
import com.metoo.nspm.core.utils.network.IpV4Util;
import org.springframework.web.socket.WebSocketSession;
import sun.misc.BASE64Decoder;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Properties;

public class WebSSh {

    public static void main(String[] args) {
        String pwd = "abcdefghijklmnopqrstuvwxyz";
        if (pwd.length() > 10) {
            pwd = pwd.substring(3);
            pwd = pwd.substring(0, pwd.length() - 7);
            System.out.println(pwd);
        }

        String ip = "192.168.5.101";
        boolean ipv4 = IpV4Util.isIp4(ip);
        System.out.println(ipv4);

        String ip4 = IpV4Util.getMatcherIP4(ip);
        System.out.println(ip4);
    }

//    public void connectToSSH(SSHConnectInfo sshConnectInfo, WebSocketSession webSocketSession,
//                             String ipv4, String loginName, String password) throws JSchException, IOException {
//
//        Session session = sshConnectInfo.getjSch().getSession(loginName, ipv4, 22);
//
//        BASE64Decoder decoder = new BASE64Decoder();
//        String pwd = new String(decoder.decodeBuffer(password), "UTF-8");
//        if (pwd.length() > 10) {
//            pwd = pwd.substring(3);
//            pwd = pwd.substring(0, pwd.length() - 7);
//        }
//        session.setPassword(pwd);
//
//        Properties config = new Properties();
//        session.setConfig(config);
//        session.setDaemonThread(true);
//        session.connect(30000);
//        Channel channel = session.openChannel("shell");
//        channel.connect(3000);
//        sshConnectInfo.setChannel(channel);
//        this.transToSSH(channel, "\r");
//
//        InputStream inputStream = channel.getInputStream();
//
//        try
//
//        {
//            byte[] buffer = new byte[1024];
//            boolean var24 = false;
//
//            int i;
//            while ((i = inputStream.read(buffer)) != -1) {
//                this.sendMessage(webSocketSession, Arrays.copyOfRange(buffer, 0, i));
//            }
//        } finally
//
//        {
//            session.disconnect();
//            channel.disconnect();
//            if (inputStream != null) {
//                inputStream.close();
//            }
//
//        }
//    }
//
//    public void transToSSH(Channel channel, String command) throws IOException {
//        if (channel != null) {
//            OutputStream outputStream = channel.getOutputStream();
//            outputStream.write(command.getBytes());
//            outputStream.flush();
//        }
//
//    }

}
